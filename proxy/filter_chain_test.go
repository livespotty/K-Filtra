package proxy

import (
	"testing"

	"github.com/grepplabs/kafka-proxy/pkg/filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockFilter is a mock implementation of the Filter interface
type MockFilter struct {
	mock.Mock
}

func (m *MockFilter) OnRequest(args filter.RequestArgs) (filter.RequestResult, error) {
	ret := m.Called(args)
	return ret.Get(0).(filter.RequestResult), ret.Error(1)
}

func (m *MockFilter) OnResponse(args filter.ResponseArgs) (filter.ResponseResult, error) {
	ret := m.Called(args)
	return ret.Get(0).(filter.ResponseResult), ret.Error(1)
}

func TestApplyRequestFilters(t *testing.T) {
	// Setup
	mockFilter1 := new(MockFilter)
	mockFilter2 := new(MockFilter)

	chain := &FilterChain{
		filters: []filter.Filter{mockFilter1, mockFilter2},
	}

	apiKey := int16(1)
	apiVersion := int16(2)
	initialBody := []byte("initial")
	modifiedBody1 := []byte("modified1")
	modifiedBody2 := []byte("modified2")

	// Expectation 1: Filter 1 called with initial body
	mockFilter1.On("OnRequest", filter.RequestArgs{
		ApiKey:     apiKey,
		ApiVersion: apiVersion,
		Body:       initialBody,
	}).Return(filter.RequestResult{Body: modifiedBody1}, nil)

	// Expectation 2: Filter 2 called with modified body from Filter 1
	mockFilter2.On("OnRequest", filter.RequestArgs{
		ApiKey:     apiKey,
		ApiVersion: apiVersion,
		Body:       modifiedBody1,
	}).Return(filter.RequestResult{Body: modifiedBody2}, nil)

	// Execute
	result, err := chain.ApplyRequestFilters(apiKey, apiVersion, initialBody)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, modifiedBody2, result)
	mockFilter1.AssertExpectations(t)
	mockFilter2.AssertExpectations(t)
}

func TestApplyResponseFilters(t *testing.T) {
	// Setup
	mockFilter1 := new(MockFilter)
	mockFilter2 := new(MockFilter)

	// Filters are stored in order [1, 2]
	chain := &FilterChain{
		filters: []filter.Filter{mockFilter1, mockFilter2},
	}

	apiKey := int16(1)
	apiVersion := int16(2)
	initialBody := []byte("initial")
	modifiedBody2 := []byte("modified2")
	modifiedBody1 := []byte("modified1")

	// Expectation 1: Filter 2 called FIRST (reverse order) with initial body
	mockFilter2.On("OnResponse", filter.ResponseArgs{
		ApiKey:     apiKey,
		ApiVersion: apiVersion,
		Body:       initialBody,
	}).Return(filter.ResponseResult{Body: modifiedBody2}, nil)

	// Expectation 2: Filter 1 called SECOND with modified body from Filter 2
	mockFilter1.On("OnResponse", filter.ResponseArgs{
		ApiKey:     apiKey,
		ApiVersion: apiVersion,
		Body:       modifiedBody2,
	}).Return(filter.ResponseResult{Body: modifiedBody1}, nil)

	// Execute
	result, err := chain.ApplyResponseFilters(apiKey, apiVersion, initialBody)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, modifiedBody1, result)
	mockFilter1.AssertExpectations(t)
	mockFilter2.AssertExpectations(t)
}
