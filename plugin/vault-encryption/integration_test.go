package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/hashicorp/vault/api"
	"github.com/livespotty/K-Filtra/pkg/filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// TestVaultEncryptionFilter_Integration runs against a REAL Vault instance AND a REAL Kafka instance.
// It requires VAULT_ADDR and VAULT_TOKEN to be set.
// It spins up Kafka/Zookeeper using Docker.
func TestVaultEncryptionFilter_Integration(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION") != "1" {
		t.Skip("integration tests disabled")
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	if vaultAddr == "" || vaultToken == "" {
		t.Skip("Skipping integration test: VAULT_ADDR and VAULT_TOKEN must be set")
	}

	ctx := context.Background()

	// 1. Start Kafka & Zookeeper (or use existing)
	var zkAddr, kafkaAddr string
	var terminateKafka func()
	var err error

	if envAddr := os.Getenv("KAFKA_ADDR"); envAddr != "" {
		t.Logf("Using existing Kafka at %s", envAddr)
		kafkaAddr = envAddr
		terminateKafka = func() {} // No-op
	} else {
		zkAddr, kafkaAddr, terminateKafka, err = startKafkaInfrastructure(ctx)
		require.NoError(t, err, "failed to start kafka infrastructure")
	}
	defer terminateKafka()

	t.Logf("Infrastructure started: ZK=%s, Kafka=%s", zkAddr, kafkaAddr)

	// 2. Setup Request Payload
	topicName := "integration-test-topic"
	originalPayload := []byte("secret-message-from-integration-test-" + time.Now().Format(time.RFC3339))
	keyPrefix := "KEK-"
	keyName := keyPrefix + topicName

	// 3. Prepare Vault (Ensure Transit Key Exists)
	config := api.DefaultConfig()
	config.Address = vaultAddr
	client, err := api.NewClient(config)
	require.NoError(t, err)
	client.SetToken(vaultToken)

	mounts, err := client.Sys().ListMounts()
	if err == nil {
		if _, ok := mounts["transit/"]; !ok {
			t.Log("Enabling transit secret engine...")
			_ = client.Sys().Mount("transit", &api.MountInput{Type: "transit"})
		}
	}
	_, err = client.Logical().Write(fmt.Sprintf("transit/keys/%s", keyName), nil)
	if err != nil {
		t.Logf("Warning: Failed to create key %s (might exist): %v", keyName, err)
	}

	// 4. Initialize Filter
	os.Setenv(VaultKeyPrefixEnv, keyPrefix)
	f, err := NewVaultEncryptionFilter()
	require.NoError(t, err)

	// 5. Create Encrypted Produce Request
	// Note: We use Version 3 for Produce Request which is widely supported and simple enough,
	// or ensure we match what the broker supports. cp-kafka 7.x supports high versions.
	// kmsg defaults to 0 if not set? We should set a version.
	// However, the filter implementation just iterates topics/partitions, so it's relatively version agnostic
	// AS LONG AS kmsg can parse the body.
	const produceVersion = 3
	batch := kmsg.NewRecordBatch()
	batch.FirstTimestamp = time.Now().UnixMilli()
	batch.Magic = 2
	record := kmsg.NewRecord()
	record.Value = originalPayload
	err = updateBatch(&batch, []kmsg.Record{record})
	require.NoError(t, err)

	produceReq := kmsg.NewProduceRequest()
	produceReq.Version = produceVersion
	produceReq.Acks = -1 // Wait for all ISR, ensures we get a response
	produceReq.TimeoutMillis = 5000
	topic := kmsg.NewProduceRequestTopic()
	topic.Topic = topicName
	partition := kmsg.NewProduceRequestTopicPartition()
	partition.Partition = 0
	partition.Records = batch.AppendTo(nil)
	topic.Partitions = append(topic.Partitions, partition)
	produceReq.Topics = append(produceReq.Topics, topic)
	// Build the body bytes the filter will see
	produceBody := produceReq.AppendTo(nil)

	// 6. Run Filter OnRequest (Encrypt)
	reqArgs := filter.RequestArgs{ApiKey: 0, ApiVersion: produceVersion, Body: produceBody}
	reqResult, err := f.OnRequest(reqArgs)
	require.NoError(t, err)

	// 7. Send Encrypted Produce Request to Real Kafka
	t.Log("Sending Encrypted Produce Request to Kafka...")
	correlationID := int32(123)
	produceRespBytes, err := sendAndReceiveKafka(kafkaAddr, 0, produceVersion, correlationID, reqResult.Body)
	require.NoError(t, err, "failed to produce to kafka")

	// Parse Produce Response to check for errors
	produceResp := kmsg.NewProduceResponse()
	produceResp.Version = produceVersion
	err = produceResp.ReadFrom(produceRespBytes)
	require.NoError(t, err, "failed to parse produce response")
	require.Equal(t, 1, len(produceResp.Topics), "expected 1 topic in response")
	require.Equal(t, 1, len(produceResp.Topics[0].Partitions), "expected 1 partition in response")

	errCode := produceResp.Topics[0].Partitions[0].ErrorCode
	require.Equal(t, int16(0), errCode, "Produce request failed with error code %d", errCode)

	// 8. Fetch from Real Kafka (to prove it's stored and we get it back)
	t.Log("Fetching from Kafka...")
	const fetchVersion = 11
	realFetchReq := kmsg.NewFetchRequest()
	realFetchReq.Version = fetchVersion
	realFetchReq.MaxWaitMillis = 500
	realFetchReq.MinBytes = 1
	realFetchReq.MaxBytes = 1024 * 1024
	fetchTopic := kmsg.NewFetchRequestTopic()
	fetchTopic.Topic = topicName
	fetchPart := kmsg.NewFetchRequestTopicPartition()
	fetchPart.Partition = 0
	fetchPart.FetchOffset = 0
	fetchTopic.Partitions = append(fetchTopic.Partitions, fetchPart)
	realFetchReq.Topics = append(realFetchReq.Topics, fetchTopic)

	fetchBody := realFetchReq.AppendTo(nil)
	fetchRespBytes, err := sendAndReceiveKafka(kafkaAddr, 1, fetchVersion, correlationID+1, fetchBody)
	require.NoError(t, err)

	// 8b. Inspect what is in the topic (Encrypted vs Decrypted)
	// We parse the rawBytes first to see what's physically in the topic
	rawResp := kmsg.NewFetchResponse()
	rawResp.Version = fetchVersion
	if err := rawResp.ReadFrom(fetchRespBytes); err == nil && len(rawResp.Topics) > 0 && len(rawResp.Topics[0].Partitions) > 0 {
		recsBytes := rawResp.Topics[0].Partitions[0].RecordBatches
		if batches, err := readRecordBatches(recsBytes); err == nil && len(batches) > 0 {
			if recs, _ := readRecords(batches[0].NumRecords, batches[0].Records); len(recs) > 0 {
				encryptedVal := recs[0].Value
				t.Logf(">>> Message in Topic (Encrypted/Raw): %x (len: %d)", encryptedVal, len(encryptedVal))
				// Optionally print as string if it helps (though it's likely binary garbage)
				// t.Logf(">>> Message in Topic (String): %s", string(encryptedVal))
			}
		}
	}

	// 9. Run Filter OnResponse (Decrypt)
	// We pass the bytes received from Kafka directly to the filter
	respArgs := filter.ResponseArgs{ApiKey: 1, ApiVersion: fetchVersion, Body: fetchRespBytes}
	respResult, err := f.OnResponse(respArgs)
	require.NoError(t, err)

	// 10. Verify Decrypted Payload
	parsedFetchResp := kmsg.NewFetchResponse()
	parsedFetchResp.Version = fetchVersion
	// We must use ReadFrom but carefully as the body might have extra bytes or exact bytes?
	// kmsg ReadFrom usually reads until done or error.
	err = parsedFetchResp.ReadFrom(respResult.Body)
	require.NoError(t, err)

	require.NotEmpty(t, parsedFetchResp.Topics)
	require.NotEmpty(t, parsedFetchResp.Topics[0].Partitions)
	decryptedRecordsBytes := parsedFetchResp.Topics[0].Partitions[0].RecordBatches
	require.NotEmpty(t, decryptedRecordsBytes, "should have received records")

	decryptedBatches, err := readRecordBatches(decryptedRecordsBytes)
	require.NoError(t, err)
	require.NotEmpty(t, decryptedBatches)
	decryptedRecs, err := readRecords(decryptedBatches[0].NumRecords, decryptedBatches[0].Records)
	require.NoError(t, err)
	require.NotEmpty(t, decryptedRecs)

	finalValue := decryptedRecs[0].Value
	t.Logf(">>> Message Decrypted by Filter: %s", string(finalValue))

	assert.Equal(t, originalPayload, finalValue, "Decrypted payload must match original")
}

// startKafkaInfrastructure starts Zookeeper and Kafka containers.
func startKafkaInfrastructure(ctx context.Context) (zkAddr string, kafkaAddr string, cleanup func(), err error) {
	// 1. Create Network
	network, err := tcnetwork.New(ctx)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create network: %w", err)
	}
	netName := network.Name

	// 2. Start Zookeeper
	zkReq := testcontainers.ContainerRequest{
		Image:    "confluentinc/cp-zookeeper:7.4.0",
		Name:     "zookeeper-" + netName, // Unique name
		Networks: []string{netName},
		NetworkAliases: map[string][]string{
			netName: {"zookeeper"},
		},
		Env: map[string]string{
			"ZOOKEEPER_CLIENT_PORT": "2181",
			"ZOOKEEPER_TICK_TIME":   "2000",
		},
		ExposedPorts: []string{"2181/tcp"},
		WaitingFor:   wait.ForLog("binding to port 0.0.0.0/0.0.0.0:2181"),
	}
	zkC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: zkReq,
		Started:          true,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to start zookeeper: %w", err)
	}

	zkHost, _ := zkC.Host(ctx)
	zkPort, _ := zkC.MappedPort(ctx, "2181")
	zkAddr = fmt.Sprintf("%s:%s", zkHost, zkPort.Port())

	// 3. Start Kafka
	// We need a free port on host to map 9092 to, so we can advertise it accurately.
	freePort, err := getFreePort()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get free port: %w", err)
	}
	kafkaPortStr := fmt.Sprintf("%d", freePort)

	kafkaReq := testcontainers.ContainerRequest{
		Image:    "confluentinc/cp-kafka:7.4.0",
		Name:     "kafka-" + netName,
		Networks: []string{netName},
		NetworkAliases: map[string][]string{
			netName: {"kafka"},
		},
		Env: map[string]string{
			"KAFKA_BROKER_ID":                                "1",
			"KAFKA_ZOOKEEPER_CONNECT":                        "zookeeper:2181",
			"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP":           "PLAINTEXT:PLAINTEXT,PLAINTEXT_INTERNAL:PLAINTEXT",
			"KAFKA_ADVERTISED_LISTENERS":                     fmt.Sprintf("PLAINTEXT://localhost:%s,PLAINTEXT_INTERNAL://kafka:29092", kafkaPortStr),
			"KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR":         "1",
			"KAFKA_TRANSACTION_STATE_LOG_MIN_ISR":            "1",
			"KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1",
		},
		ExposedPorts: []string{"9092/tcp"}, // We will bind specifically below
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.PortBindings = nat.PortMap{
				"9092/tcp": []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: kafkaPortStr,
					},
				},
			}
		},
		WaitingFor: wait.ForLog("Kafka Server started"),
	}

	kafkaC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: kafkaReq,
		Started:          true,
	})
	if err != nil {
		zkC.Terminate(ctx)
		return "", "", nil, fmt.Errorf("failed to start kafka: %w", err)
	}

	kafkaAddr = fmt.Sprintf("localhost:%s", kafkaPortStr)

	cleanup = func() {
		kafkaC.Terminate(ctx)
		zkC.Terminate(ctx)
		network.Remove(ctx)
	}

	return zkAddr, kafkaAddr, cleanup, nil
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// sendAndReceiveKafka handles the raw TCP framing
func sendAndReceiveKafka(addr string, apiKey int16, apiVersion int16, correlationID int32, body []byte) ([]byte, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 1. Build Header
	// Header v1 (ApiKey 2b, ApiVersion 2b, CorrelationId 4b, ClientId string)
	// Or Header v0?
	// Produce v9 uses Header v1 or v2?
	// Let's assume Header v1 (standard for modern).
	// [ApiKey 2][ApiVersion 2][CorrelationId 4][ClientIdLen 2][ClientId...]
	clientId := "integration-test"
	headerSize := 2 + 2 + 4 + 2 + len(clientId)
	reqSize := headerSize + len(body)

	buf := make([]byte, 4+reqSize)
	binary.BigEndian.PutUint32(buf[0:4], uint32(reqSize))

	offset := 4
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(apiKey))
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(apiVersion))
	offset += 2
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(correlationID))
	offset += 4
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(clientId)))
	offset += 2
	copy(buf[offset:], clientId)
	offset += len(clientId)

	copy(buf[offset:], body)

	// 2. Send
	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	// 3. Receive Response
	// [Length 4][CorrelationId 4][Body...]
	headerBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint32(headerBuf)

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}

	// Verify Correlation ID
	if len(respBuf) < 4 {
		return nil, fmt.Errorf("response too short")
	}
	resCorrID := binary.BigEndian.Uint32(respBuf[0:4])
	if int32(resCorrID) != correlationID {
		return nil, fmt.Errorf("correlation id mismatch: %d != %d", resCorrID, correlationID)
	}

	return respBuf[4:], nil // Return Body
}
