package filter

import (
	"net/rpc"

	"github.com/hashicorp/go-plugin"
)

// HandshakeConfig is a common handshake config for all plugins.
var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "KAFKA_PROXY_FILTER_PLUGIN",
	MagicCookieValue: "kafka-proxy-filter",
}

// Filter is the interface that we're exposing as a plugin.
type Filter interface {
	OnRequest(args RequestArgs) (RequestResult, error)
	OnResponse(args ResponseArgs) (ResponseResult, error)
}

type RequestArgs struct {
	ApiKey     int16
	ApiVersion int16
	Body       []byte
}

type RequestResult struct {
	Body []byte
}

type ResponseArgs struct {
	ApiKey     int16
	ApiVersion int16
	Body       []byte
}

type ResponseResult struct {
	Body []byte
}

// FilterPlugin is the implementation of plugin.Plugin so we can serve/consume this
//
// This has two methods: Server must return an RPC server for this plugin
// type. We construct a FilterRPCServer for this.
//
// Client must return an implementation of our interface that communicates
// over an RPC client. We return FilterRPCClient for this.
type FilterPlugin struct {
	// Impl Injection
	Impl Filter
}

func (p *FilterPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &FilterRPCServer{Impl: p.Impl}, nil
}

func (p *FilterPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &FilterRPCClient{client: c}, nil
}

// FilterRPCClient is an implementation of Filter that talks over RPC.
type FilterRPCClient struct{ client *rpc.Client }

func (g *FilterRPCClient) OnRequest(args RequestArgs) (RequestResult, error) {
	var resp RequestResult
	err := g.client.Call("Plugin.OnRequest", args, &resp)
	return resp, err
}

func (g *FilterRPCClient) OnResponse(args ResponseArgs) (ResponseResult, error) {
	var resp ResponseResult
	err := g.client.Call("Plugin.OnResponse", args, &resp)
	return resp, err
}

// FilterRPCServer is the RPC server that FilterRPCClient talks to, conforming to
// the requirements of net/rpc
type FilterRPCServer struct {
	Impl Filter
}

func (s *FilterRPCServer) OnRequest(args RequestArgs, resp *RequestResult) error {
	result, err := s.Impl.OnRequest(args)
	*resp = result
	return err
}

func (s *FilterRPCServer) OnResponse(args ResponseArgs, resp *ResponseResult) error {
	result, err := s.Impl.OnResponse(args)
	*resp = result
	return err
}
