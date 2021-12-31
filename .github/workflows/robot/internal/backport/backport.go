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
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gravitational/teleport/.github/workflows/robot/internal/github"
	"github.com/gravitational/trace"
	"gopkg.in/yaml.v2"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	input, err := parseInput()
	if err != nil {
		log.Fatal(err)
	}

	clt, err := github.New(ctx, input.token)
	if err != nil {
		log.Fatal(err)
	}

	repoOwner, repoName := input.owner, input.repo

	// The list of the commits to cherry-pick.
	// Merge commits are not supported.
	fmt.Printf("Getting commits from branch %s...\n", input.fromBranch)
	commits, err := clt.GetBranchCommits(ctx, input.owner, repoName, input.fromBranch)
	if err != nil {
		log.Fatal(err)
	}

	// Getting a PR from the branch name to later fill out new pull requests
	// with the original title and body.
	title, body, err := clt.GetPullRequestMetadata(ctx, repoOwner, repoName, input.user, input.fromBranch)
	if err != nil {
		log.Fatal(err)
	}

	for _, targetBranch := range input.backportBranches {
		// New branches will be in the format:
		// auto-backport/[release branch name]/[original branch name]
		newBranchName := fmt.Sprintf("auto-backport/%s/%s", targetBranch, input.fromBranch)

		// Create a new branch off of the target branch. Usually a release branch.
		newTargetBranch, err := clt.CreateBranchFrom(ctx, repoOwner, repoName, targetBranch, newBranchName)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Created a new branch: %s.\n", newBranchName)

		// Cherry pick commits.
		err = clt.CherryPickCommitsOnBranch(ctx, repoOwner, repoName, newTargetBranch, commits)
		if err != nil {
			log.Fatalf("Please rebase and try again: %v.\n", err)
		}
		fmt.Printf("Finished cherry-picking %v commits. \n", len(commits))

		// Create the pull request.
		err = clt.CreatePullRequest(ctx, repoOwner, repoName, targetBranch, newBranchName, title, body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Pull request created for branch %s.\n", newBranchName)
	}
	fmt.Println("Backporting complete.")
}

type GithubConfig struct {
	Github struct {
		Token    string `yaml:"oauth_token"`
		Username string `yaml:"user"`
	} `yaml:"github.com"`
}

// githubConfigPath is the default config path
// for the Github CLI tool.
const githubConfigPath = ".config/gh/hosts.yml"

// GetGithubConfig gets the Github username and auth
// token from the Github CLI config path.
func GetGithubConfig() (*GithubConfig, error) {
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	ghConfigPath := filepath.Join(dirname, githubConfigPath)
	yamlFile, err := ioutil.ReadFile(ghConfigPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return getGithubConfig(yamlFile)
}

func getGithubConfig(input []byte) (*GithubConfig, error) {
	var config *GithubConfig = new(GithubConfig)

	err := yaml.Unmarshal(input, config)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if config.Github.Token == "" {
		return nil, trace.BadParameter("missing Github token.")
	}
	if config.Github.Username == "" {
		return nil, trace.BadParameter("missing Github username.")
	}
	return config, nil
}

type Input struct {
	// backportBranches is a list of branches to backport to.
	backportBranches []string

	// from is the name of the branch to pick the commits from.
	fromBranch string

	// user is the Github username.
	user string

	// token is the Github token.
	token string

	// repo is the name of the target repository.
	repo string

	// owner is the name of the repository's (repo) organization/owner.
	owner string
}

func parseInput() (Input, error) {
	var to string
	var from string
	var repo string
	var owner string

	flag.StringVar(&to, "to", "", "List of comma-separated branch names to backport to.\n Ex: branch/v6,branch/v7\n")
	flag.StringVar(&from, "from", "", "Branch with changes to backport.")
	flag.StringVar(&repo, "repo", "", "Name of the repository to open up pull requests in.")
	flag.StringVar(&owner, "owner", "", "Name of the repository's owner.")

	flag.Parse()
	if to == "" {
		return Input{}, trace.BadParameter("must supply branches to backport to.")
	}
	if from == "" {
		return Input{}, trace.BadParameter("much supply branch with changes to backport.")
	}
	if repo == "" {
		repo = "teleport"
	}
	if owner == "" {
		owner = "gravitational"
	}

	config, err := GetGithubConfig()
	if err != nil {
		return Input{}, trace.Wrap(err)
	}

	// Parse branches to backport to.
	backportBranches, err := parseBranches(to)
	if err != nil {
		return Input{}, trace.Wrap(err)
	}

	return Input{
		backportBranches: backportBranches,
		fromBranch:       from,
		owner:            owner,
		repo:             repo,
		token:            config.Github.Token,
		user:             config.Github.Username,
	}, nil
}

// parseBranches parses a string of comma separated branch
// names into a string slice.
func parseBranches(branchesInput string) ([]string, error) {
	var backportBranches []string
	branches := strings.Split(branchesInput, ",")
	for _, branch := range branches {
		if branch == "" {
			return nil, trace.BadParameter("recieved an empty branch name.")
		}
		backportBranches = append(backportBranches, strings.TrimSpace(branch))
	}
	return backportBranches, nil
}
