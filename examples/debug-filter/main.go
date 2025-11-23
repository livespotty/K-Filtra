package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-plugin"
	"github.com/livespotty/K-Filtra/pkg/filter"
)

// DebugFilter is a simple filter that logs request and response sizes to a file.
type DebugFilter struct{}

func (f *DebugFilter) OnRequest(args filter.RequestArgs) (filter.RequestResult, error) {
	f.log(fmt.Sprintf("Request: ApiKey=%d, ApiVersion=%d, Size=%d", args.ApiKey, args.ApiVersion, len(args.Body)))
	return filter.RequestResult{Body: args.Body}, nil
}

func (f *DebugFilter) OnResponse(args filter.ResponseArgs) (filter.ResponseResult, error) {
	f.log(fmt.Sprintf("Response: ApiKey=%d, ApiVersion=%d, Size=%d", args.ApiKey, args.ApiVersion, len(args.Body)))
	return filter.ResponseResult{Body: args.Body}, nil
}

func (f *DebugFilter) log(msg string) {
	// Open file for appending
	file, err := os.OpenFile("/tmp/kafka-proxy-debug-filter.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(msg + "\n")
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: filter.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"filter": &filter.FilterPlugin{Impl: &DebugFilter{}},
		},
	})
}
