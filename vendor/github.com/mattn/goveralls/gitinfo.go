package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// A Head object encapsulates information about the HEAD revision of a git repo.
type Head struct {
	ID             string `json:"id"`
	AuthorName     string `json:"author_name,omitempty"`
	AuthorEmail    string `json:"author_email,omitempty"`
	CommitterName  string `json:"committer_name,omitempty"`
	CommitterEmail string `json:"committer_email,omitempty"`
	Message        string `json:"message"`
}

// A Git object encapsulates information about a git repo.
type Git struct {
	Head   Head   `json:"head"`
	Branch string `json:"branch"`
}

// collectGitInfo uses either environment variables or git commands to compose a Git metadata object.
func collectGitInfo(ref string) (*Git, error) {
	gitCmds := map[string][]string{
		"GIT_ID":              {"rev-parse", ref},
		"GIT_BRANCH":          {"branch", "--format", "%(refname:short)", "--contains", ref},
		"GIT_AUTHOR_NAME":     {"show", "-s", "--format=%aN", ref},
		"GIT_AUTHOR_EMAIL":    {"show", "-s", "--format=%aE", ref},
		"GIT_COMMITTER_NAME":  {"show", "-s", "--format=%cN", ref},
		"GIT_COMMITTER_EMAIL": {"show", "-s", "--format=%cE", ref},
		"GIT_MESSAGE":         {"show", "-s", "--format=%s", ref},
	}

	var gitPath string

	if *allowGitFetch && ref != "HEAD" {
		var err error
		gitPath, err = exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("failed to look path of git: %v", err)
		}

		// make sure that the commit is in the local
		// e.g. shallow cloned repository
		_, err = runCommand(gitPath, "fetch", "--depth=1", "origin", ref)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch git ref %q: %v", ref, err)
		}
	}

	for key, args := range gitCmds {
		// special case for the git branch name: load from multiple environment variables
		if key == "GIT_BRANCH" {
			if envBranch := loadBranchFromEnv(); envBranch != "" {
				err := os.Setenv(key, envBranch)
				if err != nil {
					return nil, err
				}
				continue
			}
		}
		if os.Getenv(key) != "" {
			// metadata already available via environment variable
			continue
		}

		if gitPath == "" {
			var err error
			gitPath, err = exec.LookPath("git")
			if err != nil {
				log.Printf("fail to look path of git: %v", err)
				log.Print("git information is omitted")
				return nil, nil
			}
		}

		ret, err := runCommand(gitPath, args...)
		if err != nil {
			log.Printf(`fail to run "%s %s": %v`, gitPath, strings.Join(args, " "), err)
			log.Print("git information is omitted")
			return nil, nil
		}

		err = os.Setenv(key, ret)
		if err != nil {
			return nil, err
		}
	}

	h := Head{
		ID:             os.Getenv("GIT_ID"),
		AuthorName:     os.Getenv("GIT_AUTHOR_NAME"),
		AuthorEmail:    os.Getenv("GIT_AUTHOR_EMAIL"),
		CommitterName:  os.Getenv("GIT_COMMITTER_NAME"),
		CommitterEmail: os.Getenv("GIT_COMMITTER_EMAIL"),
		Message:        os.Getenv("GIT_MESSAGE"),
	}
	g := &Git{
		Head:   h,
		Branch: os.Getenv("GIT_BRANCH"),
	}

	return g, nil
}

func runCommand(gitPath string, args ...string) (string, error) {
	cmd := exec.Command(gitPath, args...)
	ret, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	ret = bytes.TrimRight(ret, "\n")
	return string(ret), nil
}

var varNames = [...]string{
	"GIT_BRANCH",

	// https://help.github.com/en/actions/automating-your-workflow-with-github-actions/using-environment-variables
	"GITHUB_HEAD_REF", "GITHUB_REF",

	"CIRCLE_BRANCH", "TRAVIS_BRANCH",
	"CI_BRANCH", "APPVEYOR_REPO_BRANCH",
	"WERCKER_GIT_BRANCH", "DRONE_BRANCH",
	"BUILDKITE_BRANCH", "BRANCH_NAME",
	"CI_COMMIT_REF_NAME",
}

func loadBranchFromEnv() string {
	for _, varName := range varNames {
		if branch := os.Getenv(varName); branch != "" {
			if varName == "GITHUB_REF" {
				return strings.TrimPrefix(branch, "refs/heads/")
			}
			return branch
		}
	}

	return ""
}
