#!/bin/bash
set -e
unset DOCKER_HOST

# Find a free port for Kafka
echo "Finding free port for Kafka..."
KAFKA_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
echo "Selected Kafka port: $KAFKA_PORT"
export KAFKA_PORT
export TEST_ID=$(date +%s)

# Start Infrastructure (Vault + Kafka)
echo "Starting Infrastructure..."

# 1. OpenBao/Vault
echo "Starting OpenBao dev server..."
bao server -dev -dev-root-token-id=root > bao.log 2>&1 &
BAO_PID=$!

# 2. Kafka via Docker Compose
echo "Starting Kafka via Docker Compose..."
echo "DEBUG: TEST_ID=$TEST_ID KAFKA_PORT=$KAFKA_PORT"
echo "TEST_ID=$TEST_ID" > ./plugin/vault-encryption/.env
echo "KAFKA_PORT=$KAFKA_PORT" >> ./plugin/vault-encryption/.env

COMPOSE_FILE="./plugin/vault-encryption/docker-compose.yml"
COMPOSE_PROJECT_NAME="vault-encryption-$TEST_ID"

cleanup() {
    echo "Cleaning up..."
    if kill -0 $BAO_PID 2>/dev/null; then
        kill $BAO_PID
    fi
    nerdctl compose -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" down
    rm -f ./plugin/vault-encryption/.env
}
trap cleanup EXIT

nerdctl compose -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" up -d
if [ $? -ne 0 ]; then
    echo "nerdctl compose failed. Exiting."
    exit 1
fi

# Function to check if port is open
wait_for_port() {
    local port=$1
    local name=$2
    echo "Waiting for $name on port $port..."
    for i in {1..90}; do
        if nc -z 127.0.0.1 $port 2>/dev/null; then
            echo "$name is ready!"
            return 0
        fi
        sleep 1
    done
    echo "Timed out waiting for $name."
    nerdctl logs kafka-$TEST_ID
    return 1
}

wait_for_port 8200 "OpenBao"
wait_for_port $KAFKA_PORT "Kafka"

# Create Topic explicitly to ensure it exists
echo "Creating topic integration-test-topic..."
nerdctl exec kafka-$TEST_ID kafka-topics --bootstrap-server localhost:29092 --create --topic integration-test-topic --partitions 1 --replication-factor 1
if [ $? -ne 0 ]; then
    echo "Failed to create topic."
    nerdctl logs kafka-$TEST_ID
    exit 1
fi

# Give Kafka a little extra moment to stabilize
sleep 2

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"
export KAFKA_ADDR="127.0.0.1:$KAFKA_PORT"

# Run the integration test
echo "Running integration tests..."
set +e # parsing exit code manually
go test -v -tags=integration ./plugin/vault-encryption/

TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
  echo "Tests passed!"
else
  echo "Tests failed! Kafka Logs:"
  nerdctl ps -a
  nerdctl logs kafka-$TEST_ID
fi

exit $TEST_EXIT_CODE
