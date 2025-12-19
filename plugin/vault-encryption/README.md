# Vault Encryption Filter

This is a K-Filtra plugin that implements end-to-end payload encryption using HashiCorp Vault's Transit Secret Engine. Here we use OpenBao as a drop-in replacement for Vault.   

## How it works

1. **Produce**: When a producer sends a `Produce` request:
   - The filter generates a random 32-byte Data Encryption Key (DEK).
   - The DEK is encrypted using Vault's Transit Engine (using the configured key).
   - The message payload is encrypted locally using the DEK (AES-256-GCM).
   - The original payload is replaced with: `[Version][Encrypted DEK Length][Encrypted DEK][Encrypted Payload]`.
   - The request is forwarded to the broker.

2. **Consume**: When a consumer sends a `Fetch` request:
   - The broker returns the encrypted records.
   - The filter intercepts the `Fetch` response.
   - It reads the encryption header to extract the Encrypted DEK.
   - The Encrypted DEK is sent to Vault to be decrypted.
   - The decrypted DEK is used to decrypt the payload.
   - The original payload is restored, and the response is forwarded to the consumer.

## Configuration

The plugin uses environment variables for configuration:

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_ADDR` | Address of the Vault server | `https://127.0.0.1:8200` |
| `VAULT_TOKEN` | Vault token with permissions to use the transit key | (Required) |
| `VAULT_KEY_PREFIX` | Prefix for keys in Vault's transit engine. The full key name is `{PREFIX}{TopicName}` | `KEK-` |

## Prerequisites

1. **HashiCorp Vault**: You need a running Vault instance.
2. **Transit Engine**: Enable the transit engine:
   ```bash
   vault secrets enable transit
   ```
3. **Policies**: Ensure the token has permissions to encrypt/decrypt using the keys. Since keys are dynamic (`KEK-topic`), using a wildcard policy is recommended.
   ```hcl
   path "transit/encrypt/KEK-*" {
     capabilities = ["update"]
   }
   path "transit/decrypt/KEK-*" {
     capabilities = ["update"]
   }
   ```
   *Note: You must ensure keys exist in Vault or auto-creation is enabled.*
```

## Usage

Build the plugin:

```bash
go build -o vault-encryption-filter plugin/vault-encryption/main.go
```

Run K-Filtra with the plugin:

```bash
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"
./k-filtra start --filter-plugin-dir=./plugin/vault-encryption
```


## Running with Docker

You can run K-Filtra with the Vault Encryption filter pre-packaged using the provided `Dockerfile.encrypt`.

1. **Build the Image**:
   ```bash
   docker build -f Dockerfile.encrypt -t k-filtra-vault .
   ```

2. **Run the Container**:
   Ensure you have a running Kafka and Vault instance accessible to the container (e.g., via `host.docker.internal` or a shared network).

   ```bash
   docker run --rm -it \
     -e VAULT_ADDR="http://host.docker.internal:8200" \
     -e VAULT_TOKEN="root" \
     -p 9092:9092 \
     k-filtra-vault \
     server \
     --bootstrap-server-mapping "host.docker.internal:9092,0.0.0.0:19092" \
     --log-level debug
   ```

## Limitations

- Only supports `Produce` and `Fetch` requests.
- Assumes RecordBatch format (Message Format v2, Kafka 0.11+).
- Does not handle compression (yet).
- naive implementation of record batch parsing (re-calculates CRCs).

## Integration Tests

The project includes an integration test suite that verifies the filter's functionality against a real Kafka broker and a real Vault (OpenBao) instance.

### Running Tests Automated

The easiest way to run the tests is using the provided script, which uses **Docker** to spin up OpenBao (Vault alternative), Zookeeper, and Kafka, and then executes the Go tests.

```bash
./run_integration_tests.sh
```

This script will:
1. Start an OpenBao dev server (compatible with Vault).
2. Configure OpenBao with the transit engine.
3. Start Kafka and Zookeeper containers using Docker Compose.
4. Run the Go integration test (`TestVaultEncryptionFilter_Integration`).
5. Print the encrypted payload (as stored in Kafka) and the decrypted payload (as returned by the filter) to stdout.
6. Clean up all resources.

### Running Tests Manually

If you prefer to manage the infrastructure yourself:

1. **Start Vault/OpenBao**:
   ```bash
   bao server -dev -dev-root-token-id=root
   ```
2. **Start Kafka**:
   You can use the docker-compose file in the root:
   ```bash
   docker-compose up -d
   ```
3. **Run the Test**:
   Set the environment variables and run `go test`:
   ```bash
   export VAULT_ADDR="http://127.0.0.1:8200"
   export VAULT_TOKEN="root"
   # If Kafka is on localhost:9092
   export KAFKA_ADDR="localhost:9092"
   
   go test -v ./plugin/vault-encryption/...
   ```
