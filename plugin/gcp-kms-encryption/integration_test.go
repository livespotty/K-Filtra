package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
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

// TestGcpKmsEncryptionFilter_Integration runs against a Mock KMS server AND a REAL Kafka instance.
// It requires `nerdctl` to be installed and available in PATH.
func TestGcpKmsEncryptionFilter_Integration(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION") != "" {
		t.Skip("Skipping integration test")
	}

	ctx := context.Background()

	// 1. Start Mock KMS Server
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	kmspb.RegisterKeyManagementServiceServer(grpcServer, &MockKMSServer{})
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()

	t.Logf("Mock KMS Server started at %s", listener.Addr().String())

	// 2. Start Kafka & Zookeeper using nerdctl
	zkAddr, kafkaAddr, terminateKafka, err := startKafkaInfrastructure(ctx)
	require.NoError(t, err, "failed to start kafka infrastructure")
	defer terminateKafka()

	t.Logf("Infrastructure started: ZK=%s, Kafka=%s", zkAddr, kafkaAddr)

	topicName := "integration-test-topic"

	// 2.5 Ensure topic exists
	t.Logf("Creating topic %s...", topicName)
	err = createTopic(kafkaAddr, topicName)
	require.NoError(t, err, "failed to create topic")

	// 3. Setup Request Payload
	originalPayload := []byte("secret-gcp-message-" + time.Now().Format(time.RFC3339))

	// 4. Initialize Filter with Mock KMS Config
	os.Setenv(GcpProjectEnv, "test-project")
	os.Setenv(GcpLocationEnv, "global")
	os.Setenv(GcpKeyRingEnv, "test-keyring")
	os.Setenv(GcpKeyPrefix, "KEK-")
	os.Setenv("GCP_KMS_ENDPOINT", listener.Addr().String())

	// Defer unsetenv
	defer func() {
		os.Unsetenv(GcpProjectEnv)
		os.Unsetenv(GcpLocationEnv)
		os.Unsetenv(GcpKeyRingEnv)
		os.Unsetenv(GcpKeyPrefix)
		os.Unsetenv("GCP_KMS_ENDPOINT")
	}()

	f, err := NewGcpKmsEncryptionFilter()
	require.NoError(t, err)

	// 5. Create Encrypted Produce Request
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
	produceReq.Acks = -1
	produceReq.TimeoutMillis = 5000
	topic := kmsg.NewProduceRequestTopic()
	topic.Topic = topicName
	partition := kmsg.NewProduceRequestTopicPartition()
	partition.Partition = 0
	partition.Records = batch.AppendTo(nil)
	topic.Partitions = append(topic.Partitions, partition)
	produceReq.Topics = append(produceReq.Topics, topic)
	produceBody := produceReq.AppendTo(nil)

	// 6. Run Filter OnRequest (Encrypt)
	reqArgs := filter.RequestArgs{ApiKey: 0, ApiVersion: produceVersion, Body: produceBody}
	reqResult, err := f.OnRequest(reqArgs)
	require.NoError(t, err)

	// 7. Send Encrypted Produce Request to Real Kafka
	t.Log("Sending Encrypted Produce Request to Kafka...")
	correlationID := int32(123)
	var produceRespBytes []byte
	var produceResp *kmsg.ProduceResponse

	// Retry loop for the Produce request since Kafka auto-creation might take a few seconds
	maxRetries := 10
	var lastErrCode int16
	for i := 0; i < maxRetries; i++ {
		produceRespBytes, err = sendAndReceiveKafka(kafkaAddr, 0, produceVersion, correlationID, reqResult.Body)
		if err != nil {
			t.Logf("Attempt %d: sendAndReceiveKafka error: %v, retrying...", i+1, err)
			time.Sleep(2 * time.Second)
			correlationID++
			continue
		}

		resp := kmsg.NewProduceResponse()
		produceResp = &resp
		produceResp.Version = produceVersion
		if err = produceResp.ReadFrom(produceRespBytes); err != nil {
			t.Fatalf("failed to parse produce response: %v", err)
		}

		if len(produceResp.Topics) > 0 && len(produceResp.Topics[0].Partitions) > 0 {
			lastErrCode = produceResp.Topics[0].Partitions[0].ErrorCode
			if lastErrCode == 0 {
				break // Success!
			}
			t.Logf("Attempt %d: Produce failed with error code %d, retrying...", i+1, lastErrCode)
		} else {
			t.Logf("Attempt %d: Empty produce response, retrying...", i+1)
		}

		time.Sleep(2 * time.Second)
		correlationID++
	}

	require.Equal(t, int16(0), lastErrCode, "Produce request failed after retries with error code %d", lastErrCode)

	// 8. Fetch from Real Kafka
	t.Log("Fetching from Kafka...")
	const fetchVersion = 11
	correlationID++
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
	fetchRespBytes, err := sendAndReceiveKafka(kafkaAddr, 1, fetchVersion, correlationID, fetchBody)
	require.NoError(t, err)

	// 8b. Inspect raw content (Expect Mock Encrypted)
	rawResp := kmsg.NewFetchResponse()
	rawResp.Version = fetchVersion
	if err := rawResp.ReadFrom(fetchRespBytes); err == nil {
		recsBytes := rawResp.Topics[0].Partitions[0].RecordBatches
		if batches, err := readRecordBatches(recsBytes); err == nil && len(batches) > 0 {
			if recs, _ := readRecords(batches[0].NumRecords, batches[0].Records); len(recs) > 0 {
				encryptedVal := recs[0].Value
				t.Logf(">>> Message in Topic: %x", encryptedVal)
				if len(encryptedVal) > 5 {
					assert.Equal(t, uint8(EncryptionVersion), encryptedVal[0])
					dekLen := int(encryptedVal[1])<<8 | int(encryptedVal[2])
					if dekLen > 5 {
						dekContent := encryptedVal[3 : 3+dekLen]
						assert.Contains(t, string(dekContent), "mock:")
					}
				}
			}
		}
	}

	// 9. Run Filter OnResponse (Decrypt)
	respArgs := filter.ResponseArgs{ApiKey: 1, ApiVersion: fetchVersion, Body: fetchRespBytes}
	respResult, err := f.OnResponse(respArgs)
	require.NoError(t, err)

	// 10. Verify Decrypted Payload
	parsedFetchResp := kmsg.NewFetchResponse()
	parsedFetchResp.Version = fetchVersion
	err = parsedFetchResp.ReadFrom(respResult.Body)
	require.NoError(t, err)

	require.NotEmpty(t, parsedFetchResp.Topics)
	decryptedBatches, err := readRecordBatches(parsedFetchResp.Topics[0].Partitions[0].RecordBatches)
	require.NoError(t, err)
	require.NotEmpty(t, decryptedBatches)
	decryptedRecs, err := readRecords(decryptedBatches[0].NumRecords, decryptedBatches[0].Records)
	require.NoError(t, err)
	require.NotEmpty(t, decryptedRecs)

	finalValue := decryptedRecs[0].Value
	t.Logf(">>> Message Decrypted by Filter: %s", string(finalValue))

	assert.Equal(t, originalPayload, finalValue, "Decrypted payload must match original")
}

// startKafkaInfrastructure uses `nerdctl compose` to start containers.
func startKafkaInfrastructure(ctx context.Context) (zkAddr string, kafkaAddr string, cleanup func(), err error) {
	// Generate unique IDs
	runID := fmt.Sprintf("%d", time.Now().UnixNano())

	freePort, err := getFreePort()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get free port: %w", err)
	}
	kafkaPortStr := fmt.Sprintf("%d", freePort)

	// Set env vars in .env file for compose to pick up automatically
	envContent := fmt.Sprintf("TEST_ID=%s\nKAFKA_PORT=%s\n", runID, kafkaPortStr)
	if err := os.WriteFile(".env", []byte(envContent), 0644); err != nil {
		return "", "", nil, fmt.Errorf("failed to write .env file: %w", err)
	}

	// nerdctl compose -f docker-compose.yml up -d
	cmd := exec.Command("nerdctl", "compose", "-f", "docker-compose.yml", "up", "-d")
	// cmd.Env = env // No need to explicitly pass env if we have .env file, usually.
	// But let's pass current env + our vars just in case .env support is flaky in nerdctl
	cmd.Env = os.Environ()
	// However, .env file is standard for compose.

	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", nil, fmt.Errorf("failed to start compose: %v\nOutput: %s", err, string(out))
	}

	kafkaAddr = fmt.Sprintf("127.0.0.1:%s", kafkaPortStr)

	cleanup = func() {
		downCmd := exec.Command("nerdctl", "compose", "-f", "docker-compose.yml", "down", "-v")
		downCmd.Run()
		os.Remove(".env")
	}

	// Wait for Kafka to be ready
	if err := waitForPort(kafkaAddr, 60*time.Second); err != nil {
		logs, _ := exec.Command("nerdctl", "compose", "-f", "docker-compose.yml", "logs").CombinedOutput()
		cleanup()
		return "", "", nil, fmt.Errorf("kafka failed to become ready at %s: %w\nLogs:\n%s", kafkaAddr, err, string(logs))
	}

	// We don't strictly need ZK addr for the test, but if we did, we'd need to find the ephemeral port mapping if we exposed it randomly.
	// In the compose file we exposed "2181", so it's mapped to a random port.
	// For now, return empty zkAddr as the test only uses kafkaAddr.
	return "", kafkaAddr, cleanup, nil
}

// waitForPort attempts to dial the address until timeout
func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

func getContainerPort(containerName, internalPort string) (string, error) {
	// nerdctl port <container> <internalPort> check
	// Output format: 0.0.0.0:49283
	cmd := exec.Command("nerdctl", "port", containerName, internalPort)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	output := strings.TrimSpace(string(out))
	// Depending on output format, it might be "0.0.0.0:xxxxx" or "::/0:xxxxx" or similar.
	// We just want the port if we assume localhost.
	// But nerdctl/docker usually returns "0.0.0.0:12345"
	parts := strings.Split(output, ":")
	if len(parts) >= 2 {
		return "localhost:" + parts[len(parts)-1], nil
	}
	return "", fmt.Errorf("unexpected port output: %s", output)
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

func createTopic(addr, topic string) error {
	req := kmsg.NewCreateTopicsRequest()
	req.Version = 2 // Widely supported
	t := kmsg.NewCreateTopicsRequestTopic()
	t.Topic = topic
	t.NumPartitions = 1
	t.ReplicationFactor = 1
	req.Topics = append(req.Topics, t)

	correlationID := int32(999)
	respBytes, err := sendAndReceiveKafka(addr, 19, req.Version, correlationID, req.AppendTo(nil))
	if err != nil {
		return err
	}
	resp := kmsg.NewCreateTopicsResponse()
	resp.Version = req.Version
	if err := resp.ReadFrom(respBytes); err != nil {
		return err
	}
	if len(resp.Topics) > 0 && resp.Topics[0].ErrorCode != 0 && resp.Topics[0].ErrorCode != 36 { // 36 is TopicAlreadyExists
		return fmt.Errorf("create topic error: %d", resp.Topics[0].ErrorCode)
	}

	// Wait for metadata to reflect the topic is ready
	for i := 0; i < 10; i++ {
		metaReq := kmsg.NewMetadataRequest()
		metaReq.Version = 1
		mt := kmsg.NewMetadataRequestTopic()
		mt.Topic = &topic
		metaReq.Topics = append(metaReq.Topics, mt)

		metaRespBytes, err := sendAndReceiveKafka(addr, 3, metaReq.Version, correlationID+1, metaReq.AppendTo(nil))
		if err == nil {
			metaResp := kmsg.NewMetadataResponse()
			metaResp.Version = metaReq.Version
			if err := metaResp.ReadFrom(metaRespBytes); err == nil {
				if len(metaResp.Topics) > 0 && metaResp.Topics[0].ErrorCode == 0 {
					return nil // Ready
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("timeout waiting for topic metadata")
}

// sendAndReceiveKafka helpers
func sendAndReceiveKafka(addr string, apiKey int16, apiVersion int16, correlationID int32, body []byte) ([]byte, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	clientId := "integration-test"
	headerSize := 2 + 2 + 4 + 2 + len(clientId)
	reqSize := headerSize + len(body)

	buf := make([]byte, 4+reqSize)
	buf[0] = byte(reqSize >> 24)
	buf[1] = byte(reqSize >> 16)
	buf[2] = byte(reqSize >> 8)
	buf[3] = byte(reqSize)

	offset := 4
	buf[offset] = byte(apiKey >> 8)
	buf[offset+1] = byte(apiKey)
	offset += 2
	buf[offset] = byte(apiVersion >> 8)
	buf[offset+1] = byte(apiVersion)
	offset += 2
	buf[offset] = byte(correlationID >> 24)
	buf[offset+1] = byte(correlationID >> 16)
	buf[offset+2] = byte(correlationID >> 8)
	buf[offset+3] = byte(correlationID)
	offset += 4
	buf[offset] = byte(len(clientId) >> 8)
	buf[offset+1] = byte(len(clientId))
	offset += 2
	copy(buf[offset:], clientId)
	offset += len(clientId)

	copy(buf[offset:], body)

	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	headerBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return nil, err
	}
	respLen := uint32(headerBuf[0])<<24 | uint32(headerBuf[1])<<16 | uint32(headerBuf[2])<<8 | uint32(headerBuf[3])

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}

	if len(respBuf) < 4 {
		return nil, fmt.Errorf("response too short")
	}
	resCorrID := uint32(respBuf[0])<<24 | uint32(respBuf[1])<<16 | uint32(respBuf[2])<<8 | uint32(respBuf[3])
	if int32(resCorrID) != correlationID {
		return nil, fmt.Errorf("correlation id mismatch: %d != %d", resCorrID, correlationID)
	}

	return respBuf[4:], nil
}
