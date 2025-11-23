package filter

import (
	"net"
	"net/rpc"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockFilter is a mock implementation of the Filter interface
type MockFilter struct {
	mock.Mock
}

func (m *MockFilter) OnRequest(args RequestArgs) (RequestResult, error) {
	ret := m.Called(args)
	return ret.Get(0).(RequestResult), ret.Error(1)
}

func (m *MockFilter) OnResponse(args ResponseArgs) (ResponseResult, error) {
	ret := m.Called(args)
	return ret.Get(0).(ResponseResult), ret.Error(1)
}

func TestFilterRPC(t *testing.T) {
	// 1. Setup Mock
	mockFilter := new(MockFilter)

	// 2. Setup RPC Server
	rpcServer := rpc.NewServer()
	err := rpcServer.RegisterName("Plugin", &FilterRPCServer{Impl: mockFilter})
	assert.NoError(t, err)

	// 3. Setup Pipe to simulate connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// 4. Serve in a goroutine
	go rpcServer.ServeConn(serverConn)

	// 5. Setup RPC Client
	rpcClient := rpc.NewClient(clientConn)
	filterClient := &FilterRPCClient{client: rpcClient}

	// 6. Test OnRequest
	reqArgs := RequestArgs{
		ApiKey:     1,
		ApiVersion: 2,
		Body:       []byte("request"),
	}
	reqResult := RequestResult{
		Body: []byte("modified request"),
	}

	mockFilter.On("OnRequest", reqArgs).Return(reqResult, nil)

	res, err := filterClient.OnRequest(reqArgs)
	assert.NoError(t, err)
	assert.Equal(t, reqResult, res)
	mockFilter.AssertExpectations(t)

	// 7. Test OnResponse
	respArgs := ResponseArgs{
		ApiKey:     1,
		ApiVersion: 2,
		Body:       []byte("response"),
	}
	respResult := ResponseResult{
		Body: []byte("modified response"),
	}

	mockFilter.On("OnResponse", respArgs).Return(respResult, nil)

	res2, err := filterClient.OnResponse(respArgs)
	assert.NoError(t, err)
	assert.Equal(t, respResult, res2)
	mockFilter.AssertExpectations(t)
}
