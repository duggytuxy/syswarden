package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// candidateChangelogPolicy authorizes one exact unpublished change record.
// The fixed parent prevents replay later in the release chain. GitHub may
// change the commit identity during squash or rebase, so the parent and both
// complete byte streams bind the correction instead of a prospective Git SHA.
type candidateChangelogPolicy struct {
	ParentSHA       string
	Version         string
	Subject         string
	BaseSHA256      string
	CandidateSHA256 string
	HistorySHA256   string
}

var approvedCandidateChangelog = candidateChangelogPolicy{
	ParentSHA:       "703d767f3379056df52ac3f84307382ec9342b9a",
	Version:         "v4.10.3",
	Subject:         "Docs : complete the v4.10.3 correction record",
	BaseSHA256:      "b8e6c41f6fbc1196908881f83a64092dd1c186852396b66bb07ca47a749f5dfe",
	CandidateSHA256: "251666fea4e76954ba3b410827be06b162e73c2696327975ebfc0a00afe29ebd",
	HistorySHA256:   "bb34967be4fe79304870e516e510f18df5234829aaa6ac98c02cae94a3695208",
}

var approvedCandidateChangelogV4104 = candidateChangelogPolicy{
	ParentSHA:       "edf8b40a7bdd011ee788704ba30d8b355234e473",
	Version:         "v4.10.4",
	Subject:         "Fix : complete v4.10.4 security and mirror corrections",
	BaseSHA256:      "15b4656cd27f53f93232f09763a333f865e722f9b6230f6bd10d01dfef058c64",
	CandidateSHA256: "cfdf9aed98c78348ad1ef41069b5109a90b6de7f38b1663af9976a68315cac5d",
	HistorySHA256:   "6c403f15b332d5b201a986a3554ea91ebd35308c710737a18096739298e1f2bd",
}

var approvedCandidateChangelogV4104Removal = candidateChangelogPolicy{
	ParentSHA:       "6ed6a52d021fc399bc18a4b913ae037c728a8ed1",
	Version:         "v4.10.4",
	Subject:         "Fix : complete v4.10.4 native removal corrections",
	BaseSHA256:      "cfdf9aed98c78348ad1ef41069b5109a90b6de7f38b1663af9976a68315cac5d",
	CandidateSHA256: "fe62e55f5d43b109b672c040a0e3729127c84a282f57efc4f5603df62331d74b",
	HistorySHA256:   "6c403f15b332d5b201a986a3554ea91ebd35308c710737a18096739298e1f2bd",
}

var approvedCandidateChangelogV4104LegacyConfig = candidateChangelogPolicy{
	ParentSHA:       "9e82ceb01bd334795046c0c4c18b749d1447625e",
	Version:         "v4.10.4",
	Subject:         "Fix : retain inactive v4.10.4 configuration backups",
	BaseSHA256:      "fe62e55f5d43b109b672c040a0e3729127c84a282f57efc4f5603df62331d74b",
	CandidateSHA256: "dd2add8148e26fc5043a571431ef4767de502ee568fc1b2201cf2993b780d063",
	HistorySHA256:   "6c403f15b332d5b201a986a3554ea91ebd35308c710737a18096739298e1f2bd",
}

var approvedCandidateChangelogV4104RemovalRetry = candidateChangelogPolicy{
	ParentSHA:       "063848c5b0cfdd0e85ad980e4eb2dd07c0464565",
	Version:         "v4.10.4",
	Subject:         "Fix : complete v4.10.4 removal retry boundaries",
	BaseSHA256:      "dd2add8148e26fc5043a571431ef4767de502ee568fc1b2201cf2993b780d063",
	CandidateSHA256: "21f396beff5f5bbe7f94be51e349f6e98285d6c45d911fe6be27715130baba43",
	HistorySHA256:   "6c403f15b332d5b201a986a3554ea91ebd35308c710737a18096739298e1f2bd",
}

var githubSquashSuffix = regexp.MustCompile(` \(#[1-9][0-9]{0,9}\)$`)
var fullSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (app application) candidateChangelogPolicy(parentSHA string) candidateChangelogPolicy {
	if app.candidateFollowupPolicy != nil {
		return *app.candidateFollowupPolicy
	}
	if parentSHA == approvedCandidateChangelogV4104RemovalRetry.ParentSHA {
		return approvedCandidateChangelogV4104RemovalRetry
	}
	if parentSHA == approvedCandidateChangelogV4104LegacyConfig.ParentSHA {
		return approvedCandidateChangelogV4104LegacyConfig
	}
	if parentSHA == approvedCandidateChangelogV4104Removal.ParentSHA {
		return approvedCandidateChangelogV4104Removal
	}
	if parentSHA == approvedCandidateChangelogV4104.ParentSHA {
		return approvedCandidateChangelogV4104
	}
	return approvedCandidateChangelog
}

func validateCandidateChangelogCorrection(
	policy candidateChangelogPolicy,
	parentSHA string,
	previous, current Version,
	message string,
	base, candidate []byte,
) error {
	if !fullGitSHA.MatchString(policy.ParentSHA) ||
		!fullSHA256.MatchString(policy.BaseSHA256) ||
		!fullSHA256.MatchString(policy.CandidateSHA256) ||
		!fullSHA256.MatchString(policy.HistorySHA256) {
		return errors.New("candidate changelog policy contains an invalid identity")
	}
	if parentSHA != policy.ParentSHA {
		return errors.New("candidate changelog correction requires its exact reviewed parent")
	}
	if previous.String() != policy.Version || current.String() != policy.Version {
		return errors.New("candidate changelog correction must preserve its approved version")
	}
	// Accept only the exact subject, with GitHub's optional numeric squash
	// suffix. No other title wording, prefix or suffix grants this exception.
	subject := githubSquashSuffix.ReplaceAllString(commitMessageSubject(message), "")
	if subject != policy.Subject {
		return errors.New("candidate changelog correction has an unapproved subject")
	}
	if bytes.Equal(base, candidate) {
		return errors.New("candidate changelog correction requires changed bytes")
	}
	for _, item := range []struct {
		data   []byte
		digest string
		label  string
	}{
		{base, policy.BaseSHA256, "baseline"},
		{candidate, policy.CandidateSHA256, "candidate"},
	} {
		digest := sha256.Sum256(item.data)
		if hex.EncodeToString(digest[:]) != item.digest {
			return fmt.Errorf("candidate changelog %s digest does not match", item.label)
		}
	}
	_, oldHistory, oldOK := bytes.Cut(base, []byte("\n---\n"))
	_, newHistory, newOK := bytes.Cut(candidate, []byte("\n---\n"))
	if !oldOK || !newOK || !bytes.Equal(oldHistory, newHistory) {
		return errors.New("candidate changelog correction must preserve every historical byte")
	}
	historyDigest := sha256.Sum256(oldHistory)
	if hex.EncodeToString(historyDigest[:]) != policy.HistorySHA256 {
		return errors.New("candidate changelog historical digest does not match")
	}
	return nil
}

func (app application) validateUnpublishedChangelogCorrection(
	repo, baseRef string,
	previous, current Version,
	message string,
	base, candidate []byte,
) error {
	parent, err := app.git.resolveCommit(repo, baseRef)
	if err != nil {
		return err
	}
	if err := validateCandidateChangelogCorrection(app.candidateChangelogPolicy(parent), parent, previous, current, message, base, candidate); err != nil {
		return err
	}
	exists, err := app.git.tagExists(repo, current.String())
	if err != nil {
		return err
	}
	if exists {
		return errors.New("candidate changelog correction refuses an existing release tag")
	}
	head, err := app.git.resolveCommit(repo, "HEAD")
	if err != nil {
		return err
	}
	if head == parent {
		// Prospective local validation before creating the correction commit.
		return nil
	}
	parents, err := app.git.commitParents(repo, head)
	if err != nil {
		return err
	}
	if len(parents) != 1 || parents[0] != parent {
		return errors.New("candidate changelog correction must be the immediate linear child of its reviewed parent")
	}
	committed, err := app.git.fileAtRef(repo, head, changelogPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(committed, candidate) {
		return errors.New("candidate changelog correction worktree differs from its commit")
	}
	committedMessage, err := app.git.commitMessage(repo, head)
	if err != nil {
		return err
	}
	return validateCandidateChangelogCorrection(app.candidateChangelogPolicy(parent), parent, previous, current, committedMessage, base, committed)
}
