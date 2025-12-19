package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/bits"
	"os"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/vault/api"
	"github.com/livespotty/K-Filtra/pkg/filter"
	"github.com/twmb/franz-go/pkg/kmsg"
)

const (
	VaultAddressEnv   = "VAULT_ADDR"
	VaultTokenEnv     = "VAULT_TOKEN"
	VaultKeyPrefixEnv = "VAULT_KEY_PREFIX"
)

type VaultEncryptionFilter struct {
	client    *api.Client
	keyPrefix string
}

func NewVaultEncryptionFilter() (*VaultEncryptionFilter, error) {
	config := api.DefaultConfig()
	addr := os.Getenv(VaultAddressEnv)
	if addr != "" {
		config.Address = addr
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	token := os.Getenv(VaultTokenEnv)
	if token != "" {
		client.SetToken(token)
	}

	keyPrefix := os.Getenv(VaultKeyPrefixEnv)
	if keyPrefix == "" {
		keyPrefix = "KEK-" // Default key prefix
	}

	return &VaultEncryptionFilter{
		client:    client,
		keyPrefix: keyPrefix,
	}, nil
}

func (f *VaultEncryptionFilter) OnRequest(args filter.RequestArgs) (filter.RequestResult, error) {
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

func (f *VaultEncryptionFilter) OnResponse(args filter.ResponseArgs) (filter.ResponseResult, error) {
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

func (f *VaultEncryptionFilter) encryptRecords(topic string, records []byte) ([]byte, error) {
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

func (f *VaultEncryptionFilter) decryptRecords(topic string, records []byte) ([]byte, error) {
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

func (f *VaultEncryptionFilter) encryptValue(topic string, payload []byte) ([]byte, error) {
	// 1. Generate DEK
	dek := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}

	// 2. Encrypt DEK with Vault
	keyName := fmt.Sprintf("%s%s", f.keyPrefix, topic)
	dekBase64 := base64.StdEncoding.EncodeToString(dek)
	secret, err := f.client.Logical().Write(fmt.Sprintf("transit/encrypt/%s", keyName), map[string]interface{}{
		"plaintext": dekBase64,
	})
	if err != nil {
		return nil, fmt.Errorf("vault encryption failed: %w", err)
	}
	encryptedDEK := secret.Data["ciphertext"].(string)
	encryptedDEKBytes := []byte(encryptedDEK)

	// 3. Encrypt Payload with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
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

func (f *VaultEncryptionFilter) decryptValue(topic string, data []byte) ([]byte, error) {
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

	// 1. Decrypt DEK with Vault
	keyName := fmt.Sprintf("%s%s", f.keyPrefix, topic)
	secret, err := f.client.Logical().Write(fmt.Sprintf("transit/decrypt/%s", keyName), map[string]interface{}{
		"ciphertext": string(encryptedDEKBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("vault decryption failed: %w", err)
	}
	dekBase64 := secret.Data["plaintext"].(string)
	dek, err := base64.StdEncoding.DecodeString(dekBase64)
	if err != nil {
		return nil, err
	}

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
	// CRC covers everything after the CRC field.
	// We use a temporary buffer to serialize the "body" of the batch (Attributes...Records).
	// We can use batch.AppendTo to get the full bytes, then slice it.

	// We set CRC to 0 first to ensure it doesn't affect anything, though it's overwritten.
	batch.CRC = 0

	fullBytes := batch.AppendTo(nil)

	// The CRC field is at offset 17 (FirstOffset 8 + Length 4 + PartitionLeaderEpoch 4 + Magic 1).
	// CRC is bytes 17-20.
	// The data *covered* by CRC starts at byte 21.
	if len(fullBytes) < 21 {
		return fmt.Errorf("batch too short to calculate CRC")
	}

	body := fullBytes[21:]
	crc := crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli))
	batch.CRC = int32(crc) // CRC is signed int32 in struct

	// Not strictly necessary to update batch struct since we already have fullBytes,
	// but good for consistency if we reused `batch`.
	// However, we need to return the bytes with the correct CRC.
	// We can just patch fullBytes.

	binary.BigEndian.PutUint32(fullBytes[17:21], uint32(crc))

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

// --- Varint helpers based on franz-go/pkg/kmsg/internal/kbin/primitives.go ---

var uvarintLens = [256]byte{
	1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 10,
	// The rest are 0, but we only use up to 64 bits (size 9 or 10)
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
	f, err := NewVaultEncryptionFilter()
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
