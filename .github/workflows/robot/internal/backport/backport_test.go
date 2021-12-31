/*
Copyright 2021 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetGithubConfig(t *testing.T) {
	tests := []struct {
		input            string
		expectedUsername string
		expectedToken    string
		checkErr         require.ErrorAssertionFunc
		desc             string
	}{
		{
			input:    "invalid",
			desc:     "invalid-config-syntax",
			checkErr: require.Error,
		},
		{
			input: "github.com: \n  user: username \n  oauth_token: my-token",
			expectedUsername: "username",
			expectedToken:    "my-token",
			desc:             "config-is-valid",
			checkErr:         require.NoError,
		},
		{
			input: "github.com: \n  token: my-token",
			desc:     "config-is-missing-username",
			checkErr: require.Error,
		},
		{
			input: "github.com: \n  user: username",
			desc:     "config-is-missing-token",
			checkErr: require.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			expect, err := getGithubConfig([]byte(test.input))
			if expect != nil  {
				require.Equal(t, expect.Github.Token, test.expectedToken)
				require.Equal(t, expect.Github.Username, test.expectedUsername)
			}
			test.checkErr(t, err)
		})
	}
}

func TestParseBranches(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
		checkErr require.ErrorAssertionFunc
		desc     string
	}{
		{
			input:    "branch/v7",
			expected: []string{"branch/v7"},
			checkErr: require.NoError,
			desc:     "valid-branches-input-one-branch",
		},
		{
			input:    "branch/v6,branch/v7,branch/v8",
			expected: []string{"branch/v6", "branch/v7", "branch/v8"},
			checkErr: require.NoError,
			desc:     "valid-branches-input-multiple-branches",
		},
		{
			input:    "",
			expected: nil,
			checkErr: require.Error,
			desc:     "invalid-branches-input-empty-branch",
		},

		{
			input:    ",,,branch/v7",
			expected: nil,
			checkErr: require.Error,
			desc:     "invalid-branches-input-multiple-empty-branches",
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			expect, err := parseBranches(test.input)
			if test.expected != nil {
				require.ElementsMatch(t, expect, test.expected)
			}
			test.checkErr(t, err)
		})
	}
}
