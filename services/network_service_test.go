// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package services

import (
	"context"
	"testing"

	"github.com/DeckerSU/rosetta-komodo/configuration"
	"github.com/DeckerSU/rosetta-komodo/komodo"
	mocks "github.com/DeckerSU/rosetta-komodo/mocks/services"
	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/stretchr/testify/assert"
)

var (
	middlewareVersion     = "0.1.2"
	defaultNetworkOptions = &types.NetworkOptionsResponse{
		Version: &types.Version{
			RosettaVersion:    types.RosettaAPIVersion,
			NodeVersion:       "0.8.2",
			MiddlewareVersion: &middlewareVersion,
		},
		Allow: &types.Allow{
			OperationStatuses:       komodo.OperationStatuses,
			OperationTypes:          komodo.OperationTypes,
			Errors:                  Errors,
			HistoricalBalanceLookup: HistoricalBalanceLookup},
	}

	networkIdentifier = &types.NetworkIdentifier{
		Network:    komodo.MainnetNetwork,
		Blockchain: komodo.Blockchain,
	}
)

func TestNetworkEndpoints_Offline(t *testing.T) {
	cfg := &configuration.Configuration{
		Mode:    configuration.Offline,
		Network: networkIdentifier,
	}
	mockIndexer := &mocks.Indexer{}
	mockClient := &mocks.Client{}
	servicer := NewNetworkAPIService(cfg, mockClient, mockIndexer)
	ctx := context.Background()

	networkList, err := servicer.NetworkList(ctx, nil)
	assert.Nil(t, err)
	assert.Equal(t, []*types.NetworkIdentifier{
		networkIdentifier,
	}, networkList.NetworkIdentifiers)

	networkStatus, err := servicer.NetworkStatus(ctx, nil)
	assert.Nil(t, networkStatus)
	assert.Equal(t, ErrUnavailableOffline.Code, err.Code)
	assert.Equal(t, ErrUnavailableOffline.Message, err.Message)

	networkOptions, err := servicer.NetworkOptions(ctx, nil)
	assert.Nil(t, err)
	assert.Equal(t, defaultNetworkOptions, networkOptions)

	mockIndexer.AssertExpectations(t)
	mockClient.AssertExpectations(t)
}

func TestNetworkEndpoints_Online(t *testing.T) {
	cfg := &configuration.Configuration{
		Mode:                   configuration.Online,
		Network:                networkIdentifier,
		GenesisBlockIdentifier: komodo.MainnetGenesisBlockIdentifier,
	}
	mockIndexer := &mocks.Indexer{}
	mockClient := &mocks.Client{}
	servicer := NewNetworkAPIService(cfg, mockClient, mockIndexer)
	ctx := context.Background()

	networkList, err := servicer.NetworkList(ctx, nil)
	assert.Nil(t, err)
	assert.Equal(t, []*types.NetworkIdentifier{
		networkIdentifier,
	}, networkList.NetworkIdentifiers)

	blockResponse := &types.BlockResponse{
		Block: &types.Block{
			BlockIdentifier: &types.BlockIdentifier{
				Index: 100,
				Hash:  "block 100",
			},
		},
	}
	mockClient.On("GetPeers", ctx).Return([]*types.Peer{
		{
			PeerID: "77.93.223.9:7770",
		},
	}, nil)
	mockIndexer.On(
		"GetBlockLazy",
		ctx,
		(*types.PartialBlockIdentifier)(nil),
	).Return(
		blockResponse,
		nil,
	)
	networkStatus, err := servicer.NetworkStatus(ctx, nil)
	assert.Nil(t, err)
	assert.Equal(t, &types.NetworkStatusResponse{
		GenesisBlockIdentifier: komodo.MainnetGenesisBlockIdentifier,
		CurrentBlockIdentifier: blockResponse.Block.BlockIdentifier,
		Peers: []*types.Peer{
			{
				PeerID: "77.93.223.9:7770",
			},
		},
	}, networkStatus)

	networkOptions, err := servicer.NetworkOptions(ctx, nil)
	assert.Nil(t, err)
	assert.Equal(t, defaultNetworkOptions, networkOptions)

	mockIndexer.AssertExpectations(t)
	mockClient.AssertExpectations(t)
}
