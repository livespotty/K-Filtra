package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/livespotty/K-Filtra/pkg/filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kmsg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// MockKMSServer implements kmspb.KeyManagementServiceServer
type MockKMSServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

func (s *MockKMSServer) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	ciphertext := req.Ciphertext
	if len(ciphertext) < 5 || string(ciphertext[:5]) != "mock:" {
		return nil, fmt.Errorf("invalid ciphertext for mock kms")
	}

	plaintext := ciphertext[5:]
	return &kmspb.DecryptResponse{
		Plaintext: plaintext,
	}, nil
}

// Encrypt is not used in the main flow (GenerateDataKey is used), but for completeness or if logic changes
func (s *MockKMSServer) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	// Simple mock: prepend "mock:"
	return &kmspb.EncryptResponse{
		Ciphertext: append([]byte("mock:"), req.Plaintext...),
	}, nil
}

func TestGcpKmsEncryptionFilter_EndToEnd(t *testing.T) {
	// 1. Start Mock KMS Server
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer(grpc.Creds(insecure.NewCredentials())) // Server shouldn't need creds for local test?
	// Actually, the client uses insecure credentials, so the server just needs to serve plaintext HTTP/2.
	// `grpc.Creds` is for TLS. If we omit it, it's insecure.
	// But if client sends insecure, server must expect insecure. Default is insecure.
	// However, `grpc.NewServer()` creates a server that speaks plaintext if no Creds provided.

	// Wait, earlier I set `grpc.WithTransportCredentials(insecure.NewCredentials())` in client.
	// That matches a plaintext server.

	kmspb.RegisterKeyManagementServiceServer(grpcServer, &MockKMSServer{})
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()

	// 2. Setup Environment
	os.Setenv(GcpProjectEnv, "test-project")
	os.Setenv(GcpLocationEnv, "global")
	os.Setenv(GcpKeyRingEnv, "test-keyring")
	os.Setenv(GcpKeyPrefix, "KEK-")
	os.Setenv("GCP_KMS_ENDPOINT", listener.Addr().String()) // Set the mock endpoint

	defer os.Unsetenv(GcpProjectEnv)
	defer os.Unsetenv(GcpLocationEnv)
	defer os.Unsetenv(GcpKeyRingEnv)
	defer os.Unsetenv(GcpKeyPrefix)
	defer os.Unsetenv("GCP_KMS_ENDPOINT")

	// 3. Initialize Filter
	f, err := NewGcpKmsEncryptionFilter()
	require.NoError(t, err)

	originalPayload := []byte("hello gcp kms world")

	// 4. Create Produce Request
	batch := kmsg.NewRecordBatch()
	batch.FirstTimestamp = time.Now().UnixMilli()
	batch.Magic = 2
	record := kmsg.NewRecord()
	record.Value = originalPayload
	err = updateBatch(&batch, []kmsg.Record{record})
	require.NoError(t, err)

	produceReq := kmsg.NewProduceRequest()
	topic := kmsg.NewProduceRequestTopic()
	topic.Topic = "test-topic"
	partition := kmsg.NewProduceRequestTopicPartition()
	partition.Partition = 0
	partition.Records = batch.AppendTo(nil)
	topic.Partitions = append(topic.Partitions, partition)
	produceReq.Topics = append(produceReq.Topics, topic)

	reqArgs := filter.RequestArgs{
		ApiKey: 0,
		Body:   produceReq.AppendTo(nil),
	}

	// 5. Test Encryption (OnRequest)
	reqResult, err := f.OnRequest(reqArgs)
	require.NoError(t, err)

	// Verify request result
	parsedProduceReq := kmsg.NewProduceRequest()
	err = parsedProduceReq.ReadFrom(reqResult.Body)
	require.NoError(t, err)

	encryptedRecordsBytes := parsedProduceReq.Topics[0].Partitions[0].Records
	encryptedBatches, err := readRecordBatches(encryptedRecordsBytes)
	require.NoError(t, err)
	encryptedRecs, err := readRecords(encryptedBatches[0].NumRecords, encryptedBatches[0].Records)
	require.NoError(t, err)

	encryptedValue := encryptedRecs[0].Value
	assert.NotEqual(t, originalPayload, encryptedValue)
	assert.Equal(t, uint8(EncryptionVersion), encryptedValue[0])

	// Check if the "mock:" prefix can be found in the DEK part?
	// The format is [Ver][DEKLen][DEK][Payload]
	// DEKLen should be 32 (random) + 5 ("mock:") = 37
	dekLen := binary.BigEndian.Uint16(encryptedValue[1:3])
	assert.Equal(t, uint16(37), dekLen)
	wrappedDek := encryptedValue[3 : 3+dekLen]
	assert.Equal(t, "mock:", string(wrappedDek[:5]))

	// 6. Test Decryption (OnResponse)
	// Create Fetch Response mimicking Broker reaction (echoing bytes)
	fetchResp := kmsg.NewFetchResponse()
	fetchTopic := kmsg.NewFetchResponseTopic()
	fetchTopic.Topic = "test-topic"
	fetchPartition := kmsg.NewFetchResponseTopicPartition()
	fetchPartition.Partition = 0
	fetchPartition.RecordBatches = encryptedRecordsBytes
	fetchTopic.Partitions = append(fetchTopic.Partitions, fetchPartition)
	fetchResp.Topics = append(fetchResp.Topics, fetchTopic)

	respArgs := filter.ResponseArgs{
		ApiKey: 1,
		Body:   fetchResp.AppendTo(nil),
	}

	respResult, err := f.OnResponse(respArgs)
	require.NoError(t, err)

	parsedFetchResp := kmsg.NewFetchResponse()
	err = parsedFetchResp.ReadFrom(respResult.Body)
	require.NoError(t, err)

	decryptedRecordsBytes := parsedFetchResp.Topics[0].Partitions[0].RecordBatches
	decryptedBatches, err := readRecordBatches(decryptedRecordsBytes)
	require.NoError(t, err)
	decryptedRecs, err := readRecords(decryptedBatches[0].NumRecords, decryptedBatches[0].Records)
	require.NoError(t, err)

	finalValue := decryptedRecs[0].Value
	assert.Equal(t, originalPayload, finalValue)
}
