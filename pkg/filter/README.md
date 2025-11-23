# Kafka Proxy Filter Plugin

This package defines the interface for Kafka Proxy filters.
Filters are loaded as HashiCorp plugins.

## Implementing a Filter

1. Create a new Go project.
2. Implement the `filter.Filter` interface.
3. In `main`, serve the plugin using `plugin.Serve`.

Example:

```go
package main

import (
	"github.com/livespotty/K-Filtra/pkg/filter"
	"github.com/hashicorp/go-plugin"
)

type MyFilter struct{}

func (f *MyFilter) OnRequest(args filter.RequestArgs) (filter.RequestResult, error) {
	// Modify args.Body if needed
	return filter.RequestResult{Body: args.Body}, nil
}

func (f *MyFilter) OnResponse(args filter.ResponseArgs) (filter.ResponseResult, error) {
	// Modify args.Body if needed
	return filter.ResponseResult{Body: args.Body}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: filter.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"filter": &filter.FilterPlugin{Impl: &MyFilter{}},
		},
	})
}
```

## Building

Build your plugin as a standalone binary.

## Running

Run `kafka-proxy` with `--plugin-dir /path/to/plugins`.
The proxy will load all executable files in that directory as filters.
