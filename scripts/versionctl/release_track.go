package main

import "fmt"

// This is a validated classification, never a product acceptance verdict.
type releaseTrackDecision struct {
	Schema                string   `json:"schema"`
	CandidateCommit       string   `json:"candidate_commit"`
	Release               string   `json:"release"`
	PreviousVersion       string   `json:"previous_version"`
	TransitionCommit      string   `json:"transition_commit"`
	TransitionParent      string   `json:"transition_parent"`
	Prefix                BumpType `json:"prefix"`
	Track                 string   `json:"track"`
	FollowupCommits       int      `json:"followup_commits"`
	QualificationPassed   bool     `json:"qualification_passed"`
	PublicationAuthorized bool     `json:"publication_authorized"`
}

func releaseTrackForBump(bump BumpType) (string, error) {
	switch bump {
	case BumpUpgrade:
		return "full-qualification", nil
	case BumpPatch, BumpMinor, BumpMajor:
		return "intermediate-validation", nil
	default:
		return "", fmt.Errorf("no release validation track for prefix %q", bump)
	}
}
