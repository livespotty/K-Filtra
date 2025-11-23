# Debug Filter Example

This is a simple example of a Kafka Proxy filter plugin.
It logs the ApiKey, ApiVersion, and size of every request and response to `/tmp/kafka-proxy-debug-filter.log`.

## Building

```bash
go build -o debug-filter main.go
```

## Usage

1. Build the plugin:
   ```bash
   go build -o debug-filter main.go
   ```

2. Run `kafka-proxy` with the `--plugin-dir` flag pointing to the directory containing the `debug-filter` binary.

   ```bash
   ./kafka-proxy server --plugin-dir $(pwd) ...
   ```

3. Check the log file:
   ```bash
   tail -f /tmp/kafka-proxy-debug-filter.log
   ```
