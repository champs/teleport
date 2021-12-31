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

package github

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/gravitational/trace"

	go_github "github.com/google/go-github/v37/github"
	"golang.org/x/oauth2"
)

// Client implements the GitHub API.
type Client interface {
	// RequestReviewers is used to assign reviewers to a PR.
	RequestReviewers(ctx context.Context, organization string, repository string, number int, reviewers []string) error

	// ListReviews is used to list all submitted reviews for a PR.
	ListReviews(ctx context.Context, organization string, repository string, number int) (map[string]*Review, error)

	// ListPullRequests returns a list of Pull Requests.
	ListPullRequests(ctx context.Context, organization string, repository string, state string) ([]PullRequest, error)

	// ListFiles is used to list all the files within a PR.
	ListFiles(ctx context.Context, organization string, repository string, number int) ([]string, error)

	// AddLabels will add labels to an Issue or Pull Request.
	AddLabels(ctx context.Context, organization string, repository string, number int, labels []string) error

	// ListWorkflows lists all workflows within a repository.
	ListWorkflows(ctx context.Context, organization string, repository string) ([]Workflow, error)

	// ListWorkflowRuns is used to list all workflow runs for an ID.
	ListWorkflowRuns(ctx context.Context, organization string, repository string, branch string, workflowID int64) ([]Run, error)

	// DeleteWorkflowRun is used to delete a workflow run.
	DeleteWorkflowRun(ctx context.Context, organization string, repository string, runID int64) error

	// CherryPickCommitsOnBranch cherry picks a list of commits on a given branch.
	CherryPickCommitsOnBranch(ctx context.Context, organization string, repository string, branch *go_github.Branch, commits []*go_github.Commit) error

	// CherryPickCommit cherry picks a single commit on a branch.
	CherryPickCommit(ctx context.Context, organization string, repository string, branchName string, cherryCommit *go_github.Commit, headBranchCommit *go_github.Commit) (*go_github.Tree, string, error)

	// CreateBranchFrom creates a branch from the passed in branch's HEAD.
	CreateBranchFrom(ctx context.Context, organization string, repository string, branchFromName string, newBranchName string) (*go_github.Branch, error)

	// UpdateBranch updates a branch.
	UpdateBranch(ctx context.Context, organization string, repository string, branchName string, sha string) error

	// CreateCommit creates a commit.
	CreateCommit(ctx context.Context, organization string, repository string, commitMessage string, tree *go_github.Tree, parent *go_github.Commit) (string, error)

	// GetCommit gets a commit.
	GetCommit(ctx context.Context, organization string, repository string, sha string) (*go_github.Commit, error)

	// Merge merges a branch.
	Merge(ctx context.Context, organization string, repository string, base string, headCommitSHA string) (*go_github.Commit, error)

	// GetBranchCommits gets commits on a branch.
	GetBranchCommits(ctx context.Context, organization string, repository string, branchName string) ([]*go_github.Commit, error)

	// DeleteBranch deletes a branch.
	DeleteBranch(ctx context.Context, organization string, repository string, branchName string) error

	// CreatePullRequest creates a pull request.
	CreatePullRequest(ctx context.Context, organization string, repository string, baseBranch string, headBranch string, title string, body string) error

	// GetPullRequestMetadata gets a pull request's title and body by branch name.
	GetPullRequestMetadata(ctx context.Context, organization string, repository string, user string, branchName string) (title string, body string, err error)
}

type client struct {
	client *go_github.Client
}

// New returns a new GitHub client.
func New(ctx context.Context, token string) (*client, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	return &client{
		client: go_github.NewClient(oauth2.NewClient(ctx, ts)),
	}, nil
}

func (c *client) RequestReviewers(ctx context.Context, organization string, repository string, number int, reviewers []string) error {
	_, _, err := c.client.PullRequests.RequestReviewers(ctx,
		organization,
		repository,
		number,
		go_github.ReviewersRequest{
			Reviewers: reviewers,
		})
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// Review is a GitHub PR review.
type Review struct {
	// Author is the GitHub login of the user that created the PR.
	Author string
	// State is the state of the PR, for example APPROVED or CHANGES_REQUESTED.
	State string
	// SubmittedAt is the time the PR was created.
	SubmittedAt time.Time
}

func (c *client) ListReviews(ctx context.Context, organization string, repository string, number int) (map[string]*Review, error) {
	reviews := map[string]*Review{}

	opt := &go_github.ListOptions{
		Page:    0,
		PerPage: perPage,
	}
	for {
		page, resp, err := c.client.PullRequests.ListReviews(ctx,
			organization,
			repository,
			number,
			opt)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		for _, r := range page {
			// Always pick up the last submitted review from each reviewer.
			review, ok := reviews[r.GetUser().GetLogin()]
			if ok {
				if r.GetSubmittedAt().After(review.SubmittedAt) {
					review.State = r.GetState()
					review.SubmittedAt = r.GetSubmittedAt()
				}
			}

			reviews[r.GetUser().GetLogin()] = &Review{
				Author:      r.GetUser().GetLogin(),
				State:       r.GetState(),
				SubmittedAt: r.GetSubmittedAt(),
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return reviews, nil
}

// PullRequest is a Pull Requested submitted to the repository.
type PullRequest struct {
	// Author is the GitHub login of the user that created the PR.
	Author string
	// Repository is the name of the repository.
	Repository string
	// UnsafeHead is the name of the branch this PR is created from. It is marked
	// unsafe as it can be attacker controlled.
	UnsafeHead string
	// Fork determines if the pull request is from a fork.
	Fork bool
}

func (c *client) ListPullRequests(ctx context.Context, organization string, repository string, state string) ([]PullRequest, error) {
	var pulls []PullRequest

	opt := &go_github.PullRequestListOptions{
		State: state,
		ListOptions: go_github.ListOptions{
			Page:    0,
			PerPage: perPage,
		},
	}
	for {
		page, resp, err := c.client.PullRequests.List(ctx,
			organization,
			repository,
			opt)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		for _, pr := range page {
			pulls = append(pulls, PullRequest{
				Author:     pr.GetUser().GetLogin(),
				Repository: repository,
				UnsafeHead: pr.GetHead().GetRef(),
				Fork:       pr.GetHead().GetRepo().GetFork(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return pulls, nil
}

func (c *client) ListFiles(ctx context.Context, organization string, repository string, number int) ([]string, error) {
	var files []string

	opt := &go_github.ListOptions{
		Page:    0,
		PerPage: perPage,
	}
	for {
		page, resp, err := c.client.PullRequests.ListFiles(ctx,
			organization,
			repository,
			number,
			opt)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		for _, file := range page {
			files = append(files, file.GetFilename())
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return files, nil
}

// AddLabels will add labels to an Issue or Pull Request.
func (c *client) AddLabels(ctx context.Context, organization string, repository string, number int, labels []string) error {
	_, _, err := c.client.Issues.AddLabelsToIssue(ctx,
		organization,
		repository,
		number,
		labels)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// Workflow contains information about a workflow.
type Workflow struct {
	// ID of the workflow.
	ID int64
	// Name of the workflow.
	Name string
	// Path of the workflow.
	Path string
}

func (c *client) ListWorkflows(ctx context.Context, organization string, repository string) ([]Workflow, error) {
	var workflows []Workflow

	opt := &go_github.ListOptions{
		Page:    0,
		PerPage: perPage,
	}
	for {
		page, resp, err := c.client.Actions.ListWorkflows(ctx,
			organization,
			repository,
			opt)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if page.Workflows == nil {
			log.Printf("Got empty page of workflows for %v.", repository)
			continue
		}

		for _, workflow := range page.Workflows {
			workflows = append(workflows, Workflow{
				Name: workflow.GetName(),
				Path: workflow.GetPath(),
				ID:   workflow.GetID(),
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return workflows, nil
}

// Run is a specific workflow run.
type Run struct {
	// ID of the workflow run.
	ID int64
	// CreatedAt time the workflow run was created.
	CreatedAt time.Time
}

func (c *client) ListWorkflowRuns(ctx context.Context, organization string, repository string, branch string, workflowID int64) ([]Run, error) {
	var runs []Run

	opt := &go_github.ListWorkflowRunsOptions{
		Branch: branch,
		ListOptions: go_github.ListOptions{
			Page:    0,
			PerPage: perPage,
		},
	}
	for {
		page, resp, err := c.client.Actions.ListWorkflowRunsByID(ctx,
			organization,
			repository,
			workflowID,
			opt)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if page.WorkflowRuns == nil {
			log.Printf("Got empty page of workflow runs for branch: %v, workflowID: %v.", branch, workflowID)
			continue
		}

		for _, run := range page.WorkflowRuns {
			runs = append(runs, Run{
				ID:        run.GetID(),
				CreatedAt: run.GetCreatedAt().Time,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return runs, nil
}

// DeleteWorkflowRun is directly implemented because it is missing from go-github.
//
// https://docs.github.com/en/rest/reference/actions#delete-a-workflow-run
func (c *client) DeleteWorkflowRun(ctx context.Context, organization string, repository string, runID int64) error {
	url := url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   path.Join("repos", organization, repository, "actions", "runs", strconv.FormatInt(runID, 10)),
	}
	req, err := c.client.NewRequest(http.MethodDelete, url.String(), nil)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = c.client.Do(ctx, req, nil)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

const (
	// perPage is the number of items per page to request.
	perPage = 100
)

// CherryPickCommitsOnBranch cherry picks a list of commits on a given branch.
func (c *client) CherryPickCommitsOnBranch(ctx context.Context, organization string, repository string, branch *go_github.Branch, commits []*go_github.Commit) error {
	if branch.Name == nil {
		return trace.NotFound("branch name does not exist.")
	}
	if branch.Commit.SHA == nil {
		return trace.NotFound("branch %s HEAD does not exist.", *branch.Name)
	}

	headCommit, err := c.GetCommit(ctx, organization, repository, *branch.Commit.SHA)
	if err != nil {
		return trace.Wrap(err)
	}
	branchName := *branch.Name
	for i := 0; i < len(commits); i++ {
		tree, sha, err := c.CherryPickCommit(ctx, organization, repository, branchName, commits[i], headCommit)
		if err != nil {
			defer c.DeleteBranch(ctx, organization, repository, branchName)
			return trace.Wrap(err)
		}
		headCommit.SHA = &sha
		headCommit.Tree = tree
	}
	return nil
}

// CherryPickCommit cherry picks a single commit on a branch.
func (c *client) CherryPickCommit(ctx context.Context, organization string, repository string, branchName string, cherryCommit *go_github.Commit, headBranchCommit *go_github.Commit) (*go_github.Tree, string, error) {
	cherryParent := cherryCommit.Parents[0]
	// Temporarily set the parent of the branch to the parent of the commit
	// we'd like to cherry-pick so they are siblings. That way, when git performs
	// the merge, it detects that the parent of the branch commit we're merging onto matches
	// the parent of the commit we're merging with, and merges a tree of size 1, containing
	// only the cherry-pick commit.
	err := c.createSiblingCommit(ctx, organization, repository, branchName, headBranchCommit, cherryParent)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	// Merging the original cherry pick commit onto the branch.
	merge, err := c.Merge(ctx, organization, repository, branchName, *cherryCommit.SHA)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	mergeTree := merge.GetTree()

	// Get the updated HEAD commit with the new parent.
	updatedCommit, err := c.GetCommit(ctx, organization, repository, *headBranchCommit.SHA)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	// Create a new commit with the updated commit as the parent and the merge tree.
	sha, err := c.CreateCommit(ctx, organization, repository, *cherryCommit.Message, mergeTree, updatedCommit)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	// Overwrite the merge commit and its parent on the branch by the created commit.
	// The result will be equivalent to what would have happened with a fast-forward merge.
	err = c.UpdateBranch(ctx, organization, repository, branchName, sha)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	return mergeTree, sha, nil
}

// createSiblingCommit creates a commit with the passed in commit's tree and parent
// and updates the passed in branch to point at that commit.
func (c *client) createSiblingCommit(ctx context.Context, organization string, repository string, branchName string, branchHeadCommit *go_github.Commit, cherryParent *go_github.Commit) error {
	tree := branchHeadCommit.GetTree()
	// This will be the "temp" commit, commit is lost. Commit message doesn't matter.
	commitSHA, err := c.CreateCommit(ctx, organization, repository, "temp", tree, cherryParent)
	if err != nil {
		return trace.Wrap(err)
	}
	err = c.UpdateBranch(ctx, organization, repository, branchName, commitSHA)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// CreateBranchFrom creates a branch from the passed in branch's HEAD.
func (c *client) CreateBranchFrom(ctx context.Context, organization string, repository string, branchFromName string, newBranchName string) (*go_github.Branch, error) {
	baseBranch, _, err := c.client.Repositories.GetBranch(ctx,
		organization,
		repository,
		branchFromName, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	newRefBranchName := fmt.Sprintf("refs/heads/%s", newBranchName)
	baseBranchSHA := baseBranch.GetCommit().GetSHA()

	ref := &go_github.Reference{
		Ref: &newRefBranchName,
		Object: &go_github.GitObject{
			SHA: &baseBranchSHA, /* SHA to branch from */
		},
	}
	_, _, err = c.client.Git.CreateRef(ctx, organization, repository, ref)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	targetBranch, _, err := c.client.Repositories.GetBranch(ctx,
		organization,
		repository,
		newBranchName, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return targetBranch, nil
}

// UpdateBranch updates a branch.
func (c *client) UpdateBranch(ctx context.Context, organization string, repository string, branchName string, sha string) error {
	refName := fmt.Sprintf("refs/heads/%s", branchName)
	_, _, err := c.client.Git.UpdateRef(ctx, organization, repository, &go_github.Reference{
		Ref: &refName,
		Object: &go_github.GitObject{
			SHA: &sha,
		},
	}, true)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// CreateCommit creates a new commit.
func (c *client) CreateCommit(ctx context.Context, organization string, repository string, commitMessage string, tree *go_github.Tree, parent *go_github.Commit) (string, error) {
	commit, _, err := c.client.Git.CreateCommit(ctx, organization, repository, &go_github.Commit{
		Message: &commitMessage,
		Tree:    tree,
		Parents: []*go_github.Commit{
			parent,
		},
	})
	if err != nil {
		return "", trace.Wrap(err)
	}
	return commit.GetSHA(), nil
}

// GetCommit gets a commit.
func (c *client) GetCommit(ctx context.Context, organization string, repository string, sha string) (*go_github.Commit, error) {
	commit, _, err := c.client.Git.GetCommit(ctx,
		organization,
		repository,
		sha)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return commit, nil
}

// Merge merges a branch.
func (c *client) Merge(ctx context.Context, organization string, repository string, base string, headCommitSHA string) (*go_github.Commit, error) {
	merge, _, err := c.client.Repositories.Merge(ctx, organization, repository, &go_github.RepositoryMergeRequest{
		Base: &base,
		Head: &headCommitSHA,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	mergeCommit, err := c.GetCommit(ctx, organization, repository, merge.GetSHA())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return mergeCommit, nil
}

// GetBranchCommits gets commits on a branch.
//
// The only way to list commits for a branch is through RepositoriesService
// and returns type RepositoryCommit which does not contain the commit
// tree. To get the commit trees, GitService is used to get the commits (of
// type Commit) that contain the commit tree.
func (c *client) GetBranchCommits(ctx context.Context, organization string, repository string, branchName string) ([]*go_github.Commit, error) {
	// Getting RepositoryCommits.
	repoCommits, err := c.getBranchCommits(ctx, organization, repository, branchName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get the commits that are not on master. No commits will be returned if
	// the pull request from the branch to backport was not squashed and merged
	// or rebased and merged.
	comparison, _, err := c.client.Repositories.CompareCommits(ctx, organization, repository, "master", branchName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Getting Commits.
	commits := []*go_github.Commit{}
	for _, repoCommit := range repoCommits {
		for _, diffCommit := range comparison.Commits {
			if diffCommit.GetSHA() == repoCommit.GetSHA() {
				commit, err := c.GetCommit(ctx,
					organization,
					repository,
					repoCommit.GetSHA())
				if err != nil {
					return nil, trace.Wrap(err)
				}
				if len(commit.Parents) != 1 {
					return nil, trace.Errorf("merge commits are not supported.")
				}
				commits = append(commits, commit)
			}
		}
	}
	return commits, nil
}

// getBranchCommits gets commits on a branch of type go-github.RepositoryCommit.
func (c *client) getBranchCommits(ctx context.Context, organization string, repository string, branchName string) ([]*go_github.RepositoryCommit, error) {
	var repoCommits []*go_github.RepositoryCommit
	listOpts := go_github.ListOptions{
		Page:    0,
		PerPage: 100,
	}
	opts := &go_github.CommitsListOptions{SHA: branchName, ListOptions: listOpts}
	for {
		currCommits, resp, err := c.client.Repositories.ListCommits(ctx,
			organization,
			repository,
			opts)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		repoCommits = append(repoCommits, currCommits...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return repoCommits, nil
}

// DeleteBranch deletes a branch.
func (c *client) DeleteBranch(ctx context.Context, organization string, repository string, branchName string) error {
	refName := fmt.Sprintf("refs/heads/%s", branchName)
	_, err := c.client.Git.DeleteRef(ctx, organization, repository, refName)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// CreatePullRequest creates a pull request.
func (c *client) CreatePullRequest(ctx context.Context, organization string, repository string, baseBranch string, headBranch string, title string, body string) error {
	autoTitle := fmt.Sprintf("[Auto Backport] %s", title)
	newPR := &go_github.NewPullRequest{
		Title:               &autoTitle,
		Head:                &headBranch,
		Base:                &baseBranch,
		Body:                &body,
		MaintainerCanModify: go_github.Bool(true),
	}
	_, _, err := c.client.PullRequests.Create(ctx, organization, repository, newPR)
	if err != nil {
		return err
	}
	return nil
}

const (
	backportPRState          = "closed"
	backportMasterBranchName = "master"
)

// GetPullRequestMetadata gets a pull request's title and body by branch name.
func (c *client) GetPullRequestMetadata(ctx context.Context, organization string, repository string, user string, branchName string) (title string, body string, err error) {
	// TODO in a separate PR: Use c.ListPullRequests.
	// Listing PRs again with Github client directly because refactoring
	// the ListPullRequests method will require additional changes
	// outside of this package.
	prBranchName := fmt.Sprintf("%s:%s", user, branchName)
	prs, _, err := c.client.PullRequests.List(ctx,
		organization,
		repository,
		&go_github.PullRequestListOptions{
			// Get PRs that are closed and whose base is master.
			State: backportPRState,
			Base:  backportMasterBranchName,
			// Head filters pull requests by user and branch name in the format of:
			// "user:ref-name".
			Head: prBranchName,
		})
	if err != nil {
		return "", "", trace.Wrap(err)
	}
	if len(prs) == 0 {
		return "", "", trace.Errorf("pull request for branch %s does not exist", branchName)
	}
	if len(prs) != 1 {
		return "", "", trace.Errorf("found more than 1 pull request for branch %s", branchName)
	}
	pull := prs[0]
	return pull.GetTitle(), pull.GetBody(), nil
}
