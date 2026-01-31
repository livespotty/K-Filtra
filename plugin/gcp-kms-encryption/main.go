package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/bits"
	"os"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/hashicorp/go-plugin"
	"github.com/livespotty/K-Filtra/pkg/filter"
	"github.com/twmb/franz-go/pkg/kmsg"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	GcpProjectEnv  = "GCP_PROJECT_ID"
	GcpLocationEnv = "GCP_LOCATION_ID"
	GcpKeyRingEnv  = "GCP_KEY_RING_ID"
	GcpKeyPrefix   = "GCP_KEY_PREFIX"
)

type GcpKmsEncryptionFilter struct {
	client    *kms.KeyManagementClient
	projectID string
	location  string
	keyRing   string
	keyPrefix string
}

func NewGcpKmsEncryptionFilter() (*GcpKmsEncryptionFilter, error) {
	ctx := context.Background()
	var clientOpts []option.ClientOption
	clientOpts = append(clientOpts, option.WithUserAgent("k-filtra-gcp-kms-plugin/1.0"))

	// Optional Endpoint for testing/emulators
	if endpoint := os.Getenv("GCP_KMS_ENDPOINT"); endpoint != "" {
		clientOpts = append(clientOpts, option.WithEndpoint(endpoint))
		clientOpts = append(clientOpts, option.WithoutAuthentication())
		clientOpts = append(clientOpts, option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
	}

	client, err := kms.NewKeyManagementClient(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcp kms client: %w", err)
	}

	projectID := os.Getenv(GcpProjectEnv)
	if projectID == "" {
		return nil, fmt.Errorf("missing environment variable %s", GcpProjectEnv)
	}
	location := os.Getenv(GcpLocationEnv)
	if location == "" {
		return nil, fmt.Errorf("missing environment variable %s", GcpLocationEnv)
	}
	keyRing := os.Getenv(GcpKeyRingEnv)
	if keyRing == "" {
		return nil, fmt.Errorf("missing environment variable %s", GcpKeyRingEnv)
	}
	keyPrefix := os.Getenv(GcpKeyPrefix)
	if keyPrefix == "" {
		keyPrefix = "KEK-"
	}

	return &GcpKmsEncryptionFilter{
		client:    client,
		projectID: projectID,
		location:  location,
		keyRing:   keyRing,
		keyPrefix: keyPrefix,
	}, nil
}

func (f *GcpKmsEncryptionFilter) OnRequest(args filter.RequestArgs) (filter.RequestResult, error) {
	// Only handle Produce requests (ApiKey 0)
	if args.ApiKey != 0 {
		return filter.RequestResult{Body: args.Body}, nil
	}

	req := kmsg.NewProduceRequest()
	req.Version = args.ApiVersion
	if err := req.ReadFrom(args.Body); err != nil {
		return filter.RequestResult{}, fmt.Errorf("failed to parse produce request (v%d): %w", req.Version, err)
	}

	for i := range req.Topics {
		topic := &req.Topics[i]
		tName := topic.Topic
		for j := range topic.Partitions {
			partition := &topic.Partitions[j]
			newRecords, err := f.encryptRecords(tName, partition.Records)
			if err != nil {
				return filter.RequestResult{}, fmt.Errorf("failed to encrypt records: %w", err)
			}
			partition.Records = newRecords
		}
	}

	newBody := req.AppendTo(nil)
	return filter.RequestResult{Body: newBody}, nil
}

func (f *GcpKmsEncryptionFilter) OnResponse(args filter.ResponseArgs) (filter.ResponseResult, error) {
	// Only handle consumer requests (ApiKey 1)
	if args.ApiKey != 1 {
		return filter.ResponseResult{Body: args.Body}, nil
	}

	resp := kmsg.NewFetchResponse()
	resp.Version = args.ApiVersion
	if err := resp.ReadFrom(args.Body); err != nil {
		return filter.ResponseResult{}, fmt.Errorf("failed to parse fetch response (v%d): %w", resp.Version, err)
	}

	for i := range resp.Topics {
		topic := &resp.Topics[i]
		tName := topic.Topic
		for j := range topic.Partitions {
			partition := &topic.Partitions[j]
			newRecords, err := f.decryptRecords(tName, partition.RecordBatches)
			if err != nil {
				return filter.ResponseResult{}, fmt.Errorf("failed to decrypt records: %w", err)
			}
			partition.RecordBatches = newRecords
		}
	}

	newBody := resp.AppendTo(nil)
	return filter.ResponseResult{Body: newBody}, nil
}

func (f *GcpKmsEncryptionFilter) encryptRecords(topic string, records []byte) ([]byte, error) {
	if len(records) == 0 {
		return records, nil
	}

	batches, err := readRecordBatches(records)
	if err != nil {
		return records, err
	}

	for i := range batches {
		batch := &batches[i]
		rawRecords := batch.Records
		recs, err := readRecords(batch.NumRecords, rawRecords)
		if err != nil {
			return nil, err
		}

		for j := range recs {
			rec := &recs[j]
			if rec.Value == nil {
				continue
			}

			encryptedValue, err := f.encryptValue(topic, rec.Value)
			if err != nil {
				return nil, err
			}
			rec.Value = encryptedValue
		}

		if err := updateBatch(batch, recs); err != nil {
			return nil, err
		}
	}

	newBytes := make([]byte, 0)
	for _, batch := range batches {
		newBytes = batch.AppendTo(newBytes)
	}

	return newBytes, nil
}

func (f *GcpKmsEncryptionFilter) decryptRecords(topic string, records []byte) ([]byte, error) {
	if len(records) == 0 {
		return records, nil
	}

	batches, err := readRecordBatches(records)
	if err != nil {
		return records, err
	}

	for i := range batches {
		batch := &batches[i]
		rawRecords := batch.Records
		recs, err := readRecords(batch.NumRecords, rawRecords)
		if err != nil {
			return nil, err
		}

		for j := range recs {
			rec := &recs[j]
			if rec.Value == nil {
				continue
			}

			decryptedValue, err := f.decryptValue(topic, rec.Value)
			if err != nil {
				return nil, err
			}
			rec.Value = decryptedValue
		}

		if err := updateBatch(batch, recs); err != nil {
			return nil, err
		}
	}

	newBytes := make([]byte, 0)
	for _, batch := range batches {
		newBytes = batch.AppendTo(newBytes)
	}

	return newBytes, nil
}

// Encryption format:
// [1 byte version][2 bytes DEK len][Encrypted DEK][Encrypted Payload]
const (
	EncryptionVersion = 1
)

func (f *GcpKmsEncryptionFilter) encryptValue(topic string, payload []byte) ([]byte, error) {
	// Construct generic key name
	cryptoKeyID := fmt.Sprintf("%s%s", f.keyPrefix, topic)
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		f.projectID, f.location, f.keyRing, cryptoKeyID)

	// 1. Generate DEK locally
	dek := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}

	// 2. Encrypt DEK with GCP KMS
	ctx := context.Background()
	req := &kmspb.EncryptRequest{
		Name:      keyName,
		Plaintext: dek,
	}

	resp, err := f.client.Encrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcp kms encrypt failed for %s: %w", keyName, err)
	}

	encryptedDEKBytes := resp.Ciphertext

	// 3. Encrypt Payload with DEK (Local processing)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	encryptedPayload := gcm.Seal(nonce, nonce, payload, nil)

	// 4. Pack
	// Version (1) + DEK Len (2) + Encrypted DEK + Encrypted Payload
	buf := make([]byte, 1+2+len(encryptedDEKBytes)+len(encryptedPayload))
	buf[0] = EncryptionVersion
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(encryptedDEKBytes)))
	copy(buf[3:], encryptedDEKBytes)
	copy(buf[3+len(encryptedDEKBytes):], encryptedPayload)

	return buf, nil
}

func (f *GcpKmsEncryptionFilter) decryptValue(topic string, data []byte) ([]byte, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("data too short")
	}

	version := data[0]
	if version != EncryptionVersion {
		return nil, fmt.Errorf("unknown encryption version: %d", version)
	}

	dekLen := binary.BigEndian.Uint16(data[1:3])
	if len(data) < 3+int(dekLen) {
		return nil, fmt.Errorf("data too short for DEK")
	}

	encryptedDEKBytes := data[3 : 3+dekLen]
	encryptedPayload := data[3+dekLen:]

	// 1. Decrypt DEK with GCP KMS
	cryptoKeyID := fmt.Sprintf("%s%s", f.keyPrefix, topic)
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		f.projectID, f.location, f.keyRing, cryptoKeyID)

	ctx := context.Background()
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: encryptedDEKBytes,
	}

	resp, err := f.client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcp kms decrypt failed: %w", err)
	}

	dek := resp.Plaintext

	// 2. Decrypt Payload with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedPayload) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := encryptedPayload[:nonceSize], encryptedPayload[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// --- Generic Kafka Helpers (Duplicated from vault-encryption/main.go) ---
// (Identical to previous implementation)

func readRecordBatches(b []byte) ([]kmsg.RecordBatch, error) {
	var batches []kmsg.RecordBatch
	for len(b) > 0 {
		if len(b) < 12 {
			return nil, fmt.Errorf("not enough data for batch header")
		}
		length := int32(binary.BigEndian.Uint32(b[8:12]))
		totalSize := 12 + int(length)
		if len(b) < totalSize {
			return nil, fmt.Errorf("not enough data for full batch")
		}

		chunk := b[:totalSize]
		var batch kmsg.RecordBatch
		if err := batch.ReadFrom(chunk); err != nil {
			return nil, err
		}
		batches = append(batches, batch)
		b = b[totalSize:]
	}
	return batches, nil
}

func readRecords(numRecords int32, b []byte) ([]kmsg.Record, error) {
	if numRecords < 0 {
		return nil, nil // Compressed or empty
	}
	var records []kmsg.Record
	for i := int32(0); i < numRecords; i++ {
		// Peek Length (varint)
		l, n := varintDecode(b)
		if n <= 0 {
			return nil, fmt.Errorf("failed to decode record length")
		}

		// Record size = varint_size_of_length + length
		totalSize := n + int(l)
		if len(b) < totalSize {
			return nil, fmt.Errorf("not enough data for record")
		}

		chunk := b[:totalSize]
		var rec kmsg.Record
		if err := rec.ReadFrom(chunk); err != nil {
			return nil, err
		}
		records = append(records, rec)
		b = b[totalSize:]
	}
	return records, nil
}

func varintDecode(in []byte) (int32, int) {
	u, n := uvarintDecode(in)
	return int32(u>>1) ^ -int32(u&1), n
}

func uvarintDecode(in []byte) (uint32, int) {
	var x uint32
	var s uint
	for i, b := range in {
		if i >= 5 {
			return 0, -i
		}
		if b < 0x80 {
			if i > 9 || (i == 9 && b > 1) {
				return 0, -i // overflow
			}
			return x | uint32(b)<<s, i + 1
		}
		x |= uint32(b&0x7f) << s
		s += 7
	}
	return 0, 0
}

func updateBatch(batch *kmsg.RecordBatch, recs []kmsg.Record) error {
	// 1. Re-serialize records and update their lengths
	newRawRecords := make([]byte, 0)
	for i := range recs {
		rec := &recs[i]
		// Calculate Length
		rec.Length = calculateRecordLength(rec)
		newRawRecords = rec.AppendTo(newRawRecords)
	}
	batch.Records = newRawRecords
	batch.NumRecords = int32(len(recs))

	// 2. Update Batch Length
	// Length = 49 (header size after Length field) + len(Records)
	batch.Length = 49 + int32(len(batch.Records))

	// 3. Update CRC
	batch.CRC = 0

	fullBytes := batch.AppendTo(nil)

	if len(fullBytes) < 21 {
		return fmt.Errorf("batch too short to calculate CRC")
	}

	body := fullBytes[21:]
	crc := crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli))
	batch.CRC = int32(crc) // CRC is signed int32 in struct

	return nil
}

func calculateRecordLength(r *kmsg.Record) int32 {
	l := 0
	l += 1 // Attributes int8
	l += varlongLen(r.TimestampDelta64)
	l += varintLen(r.OffsetDelta)
	l += varintBytesLen(r.Key)
	l += varintBytesLen(r.Value)

	// Headers count
	l += varintLen(int32(len(r.Headers)))
	for _, h := range r.Headers {
		l += varintStringLen(h.Key)
		l += varintBytesLen(h.Value)
	}
	return int32(l)
}

// --- Varint helpers ---

var uvarintLens = [256]byte{
	1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 10,
}

func uvarintLen(u uint32) int {
	return int(uvarintLens[byte(bits.Len32(u))])
}

func uvarlongLen(u uint64) int {
	return int(uvarintLens[byte(bits.Len64(u))])
}

func varintLen(i int32) int {
	u := uint32(i)<<1 ^ uint32(i>>31)
	return uvarintLen(u)
}

func varlongLen(i int64) int {
	u := uint64(i)<<1 ^ uint64(i>>63)
	return uvarlongLen(u)
}

func varintBytesLen(b []byte) int {
	if b == nil {
		return varintLen(-1)
	}
	return varintLen(int32(len(b))) + len(b)
}

func varintStringLen(s string) int {
	return varintLen(int32(len(s))) + len(s)
}

func main() {
	f, err := NewGcpKmsEncryptionFilter()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing filter: %s\n", err)
		os.Exit(1)
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: filter.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"filter": &filter.FilterPlugin{Impl: f},
		},
	})
}
