# GCP KMS Encryption Filter Plugin

This plugin implements envelope encryption for Kafka records using Google Cloud KMS.
It uses a similar approach to the Vault Encryption plugin but interfaces with GCP KMS.

## How it works

1. **Produce (Encryption)**:
    - For each record, the plugin constructs a Key Name based on the topic: `projects/{p}/locations/{l}/keyRings/{k}/cryptoKeys/{prefix}{topic}`.
    - It generates a local random 32-byte Data Encryption Key (DEK).
    - It calls `Encrypt` on GCP KMS to encrypt this DEK using the specified Key Encryption Key (KEK).
    - It encrypts the record payload using the local DEK (AES-GCM).
    - It packages the result: `[Version (1 byte)][DEK Length (2 bytes)][Encrypted DEK][Encrypted Payload]`.
    - The local DEK is discarded from memory.

2. **Consume (Decryption)**:
    - The plugin parses the `[Version][DEK Length][Encrypted DEK][Encrypted Payload]` structure.
    - It calls `Decrypt` on GCP KMS using the `Encrypted DEK`.
    - It receives the `plaintext` DEK.
    - It decrypts the payload using the DEK.

## Data Privacy & Performance (Envelope Encryption)

It is important to understand where your data is processed:

1.  **Payload Processing**: The actual encryption and decryption of your Kafka message payloads happens **LOCALLY** within the K-Filtra process (sidecar/proxy). Your message payload **never** leaves your infrastructure and is **never** sent to Google Cloud KMS.
2.  **Key Processing**: Only the randomly generated Data Encryption Keys (DEKs) are sent to GCP KMS to be encrypted/decrypted.
3.  **Performance**: Since GCP KMS is only involved in encrypting/decrypting small 32-byte keys, the performance overhead is minimal compared to sending full payloads to a remote service. This architecture is standard for high-throughput systems.

## Configuration

The plugin is configured via environment variables:

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `GCP_PROJECT_ID` | Google Cloud Project ID | Yes | - |
| `GCP_LOCATION_ID` | GCP Location (e.g., `global`, `us-east1`) | Yes | - |
| `GCP_KEY_RING_ID` | GCP Key Ring ID | Yes | - |
| `GCP_KEY_PREFIX` | Prefix for the CryptoKey name constructed as `{Prefix}{TopicName}` | No | `KEK-` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON (Standard ADC) | Yes/ADC | - |

## Prerequisites

- Ensure the GCP KMS Key Ring exists.
- Ensure CryptoKeys exist for each topic you intend to encrypt (e.g. `KEK-my-topic`).
- The Service Account used must have `cloudkms.cryptoKeyVersions.useToEncrypt` and `cloudkms.cryptoKeyVersions.useToDecrypt` permissions (e.g. `roles/cloudkms.cryptoKeyEncrypterDecrypter`).

## Usage

Build the plugin:

```bash
go build -o gcp-kms-encryption-filter plugin/gcp-kms-encryption/main.go
```

Run K-Filtra with the plugin:

```bash
export GCP_PROJECT_ID="my-project"
export GCP_LOCATION_ID="global"
export GCP_KEY_RING_ID="my-keyring"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/creds.json"
./k-filtra start --filter-plugin-dir=./plugin/gcp-kms-encryption
```

## Integration Tests

The project includes an integration test suite that verifies the filter's functionality against a real Kafka broker and a Mock KMS server (so no real GCP costs or credentials are required for testing).

### Running Tests Automated

The integration tests rely on `nerdctl` (or Docker compatible CLI) to spin up a Kafka and Zookeeper environment.

1. **Install nerdctl/Docker**: Ensure `nerdctl` is in your PATH and configured (e.g., via Rancher Desktop).
2. **Run the Test**:

```bash
cd plugin/gcp-kms-encryption
go test -v -run TestGcpKmsEncryptionFilter_Integration .
```

This test will:
1. Start a local mock gRPC server mimicking GCP KMS.
2. Spin up Kafka and Zookeeper containers using `nerdctl compose` and the `docker-compose.yml`.
3. Produce an encrypted message.
4. Verify the message is encrypted in the broker.
5. Consume the message and verify it is correctly decrypted.
6. Clean up the containers and network.

### Note on Test Environment

If you typically use `docker` instead of `nerdctl`, you can alias it or modify the test to use `docker` commands, but `nerdctl compose` is currently hardcoded in `integration_test.go`.

**Troubleshooting Tests:**
- If tests time out waiting for Kafka, ensure your `docker-compose.yml` allows port mapping and that no other service is binding port 9092.
- If you see `unknown topic or partition` errors, retry; the test environment might take a few seconds for the broker to fully initialize metadata.
