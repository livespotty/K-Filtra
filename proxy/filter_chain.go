package proxy

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/livespotty/K-Filtra/pkg/filter"
	"github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"
)

type FilterChain struct {
	filters []filter.Filter
	clients []*plugin.Client
}

func NewFilterChain(pluginDir string) (*FilterChain, error) {
	chain := &FilterChain{}

	if pluginDir == "" {
		return chain, nil
	}

	files, err := ioutil.ReadDir(pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			return chain, nil
		}
		return nil, err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		// Assume executable files are plugins
		if f.Mode()&0111 != 0 {
			path := filepath.Join(pluginDir, f.Name())
			logrus.Infof("Loading plugin: %s", path)

			client := plugin.NewClient(&plugin.ClientConfig{
				HandshakeConfig: filter.HandshakeConfig,
				Plugins: map[string]plugin.Plugin{
					"filter": &filter.FilterPlugin{},
				},
				Cmd: exec.Command(path),
			})

			rpcClient, err := client.Client()
			if err != nil {
				logrus.Errorf("Error creating client for plugin %s: %v", path, err)
				continue
			}

			raw, err := rpcClient.Dispense("filter")
			if err != nil {
				logrus.Errorf("Error dispensing plugin %s: %v", path, err)
				continue
			}

			chain.filters = append(chain.filters, raw.(filter.Filter))
			chain.clients = append(chain.clients, client)
		}
	}

	return chain, nil
}

func (c *FilterChain) Close() {
	for _, client := range c.clients {
		client.Kill()
	}
}

func (c *FilterChain) ApplyRequestFilters(apiKey, apiVersion int16, body []byte) ([]byte, error) {
	currentBody := body
	for _, f := range c.filters {
		args := filter.RequestArgs{
			ApiKey:     apiKey,
			ApiVersion: apiVersion,
			Body:       currentBody,
		}
		res, err := f.OnRequest(args)
		if err != nil {
			return nil, err
		}
		currentBody = res.Body
	}
	return currentBody, nil
}

func (c *FilterChain) ApplyResponseFilters(apiKey, apiVersion int16, body []byte) ([]byte, error) {
	currentBody := body
	// Apply in reverse order
	for i := len(c.filters) - 1; i >= 0; i-- {
		f := c.filters[i]
		args := filter.ResponseArgs{
			ApiKey:     apiKey,
			ApiVersion: apiVersion,
			Body:       currentBody,
		}
		res, err := f.OnResponse(args)
		if err != nil {
			return nil, err
		}
		currentBody = res.Body
	}
	return currentBody, nil
}
