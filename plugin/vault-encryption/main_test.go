package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/livespotty/K-Filtra/pkg/filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kmsg"
)

func TestVaultEncryptionFilter_EndToEnd(t *testing.T) {
	// 1. Mock Vault Server
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" && r.Method != "PUT" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if strings.Contains(r.URL.Path, "/encrypt/") {
			// Encrypt: plaintext -> ciphertext
			plaintext, _ := req["plaintext"].(string)
			// Simple mock encryption: prefix with "enc:"
			ciphertext := "enc:" + plaintext
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"ciphertext": ciphertext,
				},
			}
			json.NewEncoder(w).Encode(resp)
		} else if strings.Contains(r.URL.Path, "/decrypt/") {
			// Decrypt: ciphertext -> plaintext
			ciphertext, _ := req["ciphertext"].(string)
			if strings.HasPrefix(ciphertext, "enc:") {
				plaintext := strings.TrimPrefix(ciphertext, "enc:")
				resp := map[string]interface{}{
					"data": map[string]interface{}{
						"plaintext": plaintext,
					},
				}
				json.NewEncoder(w).Encode(resp)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer vaultServer.Close()

	// 2. Setup Environment
	os.Setenv(VaultAddressEnv, vaultServer.URL)
	os.Setenv(VaultTokenEnv, "test-token")
	os.Setenv(VaultKeyPrefixEnv, "KEK-")
	defer os.Unsetenv(VaultAddressEnv)
	defer os.Unsetenv(VaultTokenEnv)
	defer os.Unsetenv(VaultKeyPrefixEnv)

	// 3. Initialize Filter
	f, err := NewVaultEncryptionFilter()
	require.NoError(t, err)

	originalPayload := []byte("hello kafka world")

	// 4. Create Produce Request (Client -> Broker)
	// We construct a RecordBatch with one record containing the payload.
	batch := kmsg.NewRecordBatch()
	batch.FirstTimestamp = time.Now().UnixMilli()
	batch.Magic = 2

	record := kmsg.NewRecord()
	record.Value = originalPayload

	// We need to use updateBatch to correctly calculate Lengths/CRC before serializing
	// But updateBatch takes []kmsg.Record.
	err = updateBatch(&batch, []kmsg.Record{record})
	require.NoError(t, err)

	// Serialize the batch to bytes
	recordsBytes := batch.AppendTo(nil)

	// Wrap in ProduceRequest
	produceReq := kmsg.NewProduceRequest()
	topic := kmsg.NewProduceRequestTopic()
	topic.Topic = "test-topic"
	partition := kmsg.NewProduceRequestTopicPartition()
	partition.Partition = 0
	partition.Records = recordsBytes
	topic.Partitions = append(topic.Partitions, partition)
	produceReq.Topics = append(produceReq.Topics, topic)

	reqArgs := filter.RequestArgs{
		ApiKey: 0, // Produce
		Body:   produceReq.AppendTo(nil),
	}

	// 5. Run OnRequest (Encrypt)
	reqResult, err := f.OnRequest(reqArgs)
	require.NoError(t, err)

	// 6. Verify Encryption
	// Parse the result body
	parsedProduceReq := kmsg.NewProduceRequest()
	err = parsedProduceReq.ReadFrom(reqResult.Body)
	require.NoError(t, err)

	require.NotEmpty(t, parsedProduceReq.Topics)
	require.NotEmpty(t, parsedProduceReq.Topics[0].Partitions)
	encryptedRecordsBytes := parsedProduceReq.Topics[0].Partitions[0].Records

	// The length should be different (likely larger due to header + encryption overhead)
	// Actually strictly checking length is hard, but it shouldn't be identical if encryption happened.
	assert.NotEqual(t, recordsBytes, encryptedRecordsBytes)

	// Read the encrypted batch to inspect the first record
	encryptedBatches, err := readRecordBatches(encryptedRecordsBytes)
	require.NoError(t, err)
	require.Len(t, encryptedBatches, 1)

	encryptedRecs, err := readRecords(encryptedBatches[0].NumRecords, encryptedBatches[0].Records)
	require.NoError(t, err)
	require.Len(t, encryptedRecs, 1)

	encryptedValue := encryptedRecs[0].Value
	assert.NotEqual(t, originalPayload, encryptedValue)
	// Check header version byte
	assert.Equal(t, uint8(EncryptionVersion), encryptedValue[0], "Encryption version mismatch")

	// 7. Create Fetch Response (Broker -> Client)
	// We simulate the broker returning the ENCRYPTED bytes we just got.
	fetchResp := kmsg.NewFetchResponse()
	fetchTopic := kmsg.NewFetchResponseTopic()
	fetchTopic.Topic = "test-topic"
	fetchPartition := kmsg.NewFetchResponseTopicPartition()
	fetchPartition.Partition = 0
	fetchPartition.RecordBatches = encryptedRecordsBytes // The broker stores what we sent
	fetchTopic.Partitions = append(fetchTopic.Partitions, fetchPartition)
	fetchResp.Topics = append(fetchResp.Topics, fetchTopic)

	respArgs := filter.ResponseArgs{
		ApiKey: 1, // Fetch
		Body:   fetchResp.AppendTo(nil),
	}

	// 8. Run OnResponse (Decrypt)
	respResult, err := f.OnResponse(respArgs)
	require.NoError(t, err)

	// 9. Verify Decryption
	parsedFetchResp := kmsg.NewFetchResponse()
	err = parsedFetchResp.ReadFrom(respResult.Body)
	require.NoError(t, err)

	require.NotEmpty(t, parsedFetchResp.Topics)
	require.NotEmpty(t, parsedFetchResp.Topics[0].Partitions)
	decryptedRecordsBytes := parsedFetchResp.Topics[0].Partitions[0].RecordBatches

	// Parse decrypted batch
	decryptedBatches, err := readRecordBatches(decryptedRecordsBytes)
	require.NoError(t, err)
	require.Len(t, decryptedBatches, 1)

	decryptedRecs, err := readRecords(decryptedBatches[0].NumRecords, decryptedBatches[0].Records)
	require.NoError(t, err)
	require.Len(t, decryptedRecs, 1)

	finalValue := decryptedRecs[0].Value

	// 10. Final Assertion
	assert.Equal(t, originalPayload, finalValue, "Decrypted payload should match original")
}
