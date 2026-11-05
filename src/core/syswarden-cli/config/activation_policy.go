package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

const activationPolicySchema = "syswarden-activation-policy-v1"
const activationPolicyEnvironment = "toml-only-reject-modular-environment-v1"

// ActivationPolicy is an immutable capture of validated effective TOML policy.
// It grants no approval, write lease, host mutation or runtime acceptance. A
// consuming activation boundary must separately bind reviewed host changes and
// revalidate this capture immediately before using its returned configuration.
type ActivationPolicy struct {
	root          string
	snapshot      *mergedConfigSnapshot
	configuration *Config
	review        ActivationPolicyReview
}

// ActivationPolicyReview contains no policy values, source paths or credentials.
// Digest binds this exact source inventory, metadata and effective configuration;
// it is evidence for a consuming approval boundary, never approval by itself.
type ActivationPolicyReview struct {
	Digest             string
	InputCount         int
	ModulePlan         []string
	Effects            []ConfigurationEffect
	UnknownKeyCount    int
	DeprecatedKeyCount int
}

// CaptureActivationPolicy reads the existing complete modular configuration.
// It neither normalizes compatibility inputs nor writes files or GlobalConfig.
// Actual modular environment namespaces are rejected, including empty values;
// package and qualification variables outside those namespaces remain allowed.
func CaptureActivationPolicy(ctx context.Context, root string) (*ActivationPolicy, error) {
	if err := activationPolicyContext(ctx); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("activation policy root must be absolute and canonical")
	}
	if err := rejectActivationPolicyEnvironment(); err != nil {
		return nil, err
	}
	target := userTOMLTarget()
	before, content, err := captureModuleInputs(root, target, nil)
	if err != nil {
		return nil, err
	}
	if err := requireCompleteActivationPolicy(before); err != nil {
		return nil, err
	}
	if err := before.requireEditOwnership(os.Geteuid()); err != nil {
		return nil, err
	}
	if err := before.requireEditRecoveryMetadata(); err != nil {
		return nil, err
	}
	validated, err := validateModuleCandidate(root, target, content, before.identity(target))
	if err != nil {
		return nil, err
	}
	if !sameUserModuleBaseline(before, validated) {
		return nil, errors.New("activation policy changed during validation")
	}
	modular, candidate, err := decodeActivationPolicy(root, before)
	if err != nil {
		return nil, err
	}
	digest, err := activationPolicyDigest(root, before, modular)
	if err != nil {
		return nil, err
	}
	policy := &ActivationPolicy{
		root: root, snapshot: before, configuration: candidate,
		review: ActivationPolicyReview{
			Digest: digest, InputCount: len(before.moduleNames) + 1,
			ModulePlan: ModulePlan(candidate), Effects: configurationEffects(modular),
			UnknownKeyCount: len(validated.report.UnknownKeys), DeprecatedKeyCount: len(validated.report.DeprecatedKeys),
		},
	}
	if err := policy.Revalidate(ctx); err != nil {
		return nil, err
	}
	return policy, nil
}

// Completeness belongs to the same bounded snapshot used by validation and
// decoding. A separate earlier filesystem pass could accept a module that is
// absent from the captured policy and permit historical defaults to replace it.
func requireCompleteActivationPolicy(snapshot *mergedConfigSnapshot) error {
	if snapshot == nil || snapshot.master == nil || snapshot.user == nil {
		return errors.New("activation policy capture requires complete existing modular configuration")
	}
	for _, name := range []string{"00-core.toml", "10-network.toml", "20-security.toml", "30-waap.toml", "40-integrations.toml"} {
		if snapshot.modules[name] == nil {
			return errors.New("activation policy capture requires complete existing modular configuration")
		}
	}
	return nil
}

// Review returns independent copies of the captured descriptions. It observes
// no new state; callers must use Revalidate before treating the capture as current.
func (policy *ActivationPolicy) Review() ActivationPolicyReview {
	if policy == nil || policy.snapshot == nil || policy.configuration == nil {
		return ActivationPolicyReview{}
	}
	review := policy.review
	review.ModulePlan = append([]string(nil), review.ModulePlan...)
	review.Effects = append([]ConfigurationEffect(nil), review.Effects...)
	return review
}

// Revalidate refuses source replacement, metadata or inventory drift, pending
// edits/migration and newly introduced environment overlays. It grants no lease
// against a later concurrent privileged write and never recaptures a new policy.
func (policy *ActivationPolicy) Revalidate(ctx context.Context) error {
	if err := activationPolicyContext(ctx); err != nil {
		return err
	}
	if policy == nil || policy.snapshot == nil || policy.configuration == nil || policy.review.Digest == "" {
		return errors.New("activation policy capture is unavailable")
	}
	if err := rejectActivationPolicyEnvironment(); err != nil {
		return err
	}
	if err := RefusePendingModuleEdit(policy.root); err != nil {
		return err
	}
	if err := policy.snapshot.revalidate(policy.root, false, nil); err != nil {
		return fmt.Errorf("activation policy changed since capture: %w", err)
	}
	if err := RefusePendingModuleEdit(policy.root); err != nil {
		return err
	}
	if err := rejectActivationPolicyEnvironment(); err != nil {
		return err
	}
	return activationPolicyContext(ctx)
}

// Configuration returns a deep copy of the originally captured effective
// configuration after revalidation. It does not install the copy globally or
// confer authority to apply it. Later reads never reinterpret new environment.
func (policy *ActivationPolicy) Configuration(ctx context.Context) (*Config, error) {
	if err := policy.Revalidate(ctx); err != nil {
		return nil, err
	}
	copy := *policy.configuration
	copy.HAPeerCertSHA256 = append([]string(nil), policy.configuration.HAPeerCertSHA256...)
	copy.OperatorPolicy = cloneOperatorPolicy(policy.configuration.OperatorPolicy)
	if source := policy.configuration.operatorPolicySource; source != nil {
		cloned := *source
		cloned.policy = cloneOperatorPolicy(source.policy)
		if source.identity != nil {
			identity := *source.identity
			cloned.identity = &identity
		}
		copy.operatorPolicySource = &cloned
	}
	return &copy, nil
}

func activationPolicyContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("activation policy capture requires a context")
	}
	return ctx.Err()
}

// Derive namespaces from the actual modular schema so a new top-level section
// cannot silently acquire AutomaticEnv semantics outside this capture contract.
// Reject the section itself as well as descendants and aliases within it.
func rejectActivationPolicyEnvironment() error {
	schema := reflect.TypeOf(ModularConfig{})
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		for index := 0; index < schema.NumField(); index++ {
			section := strings.Split(schema.Field(index).Tag.Get("mapstructure"), ",")[0]
			if section == "" || section == "-" {
				return errors.New("activation policy schema has an unsupported environment namespace")
			}
			prefix := "SYSWARDEN_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(section))
			if name == prefix || strings.HasPrefix(name, prefix+"_") {
				return errors.New("activation policy requires TOML-only configuration; remove modular configuration environment overrides before capture or use")
			}
		}
	}
	return nil
}

// The existing merged validator establishes the source contract first. Decode
// the same bounded, identity-pinned bytes with the runtime's shared defaults,
// alias resolution and validation, without invoking its process-global loader.
func decodeActivationPolicy(root string, snapshot *mergedConfigSnapshot) (*ModularConfig, *Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	setDefaults(v, root)
	observed := make(map[string]struct{})
	var inventory unconfiguredProfileInventory
	merge := func(directory, name, relative string, expected *secureFileIdentity) error {
		opened, err := openConfigDirectory(directory, false, 0)
		if err != nil {
			return err
		}
		defer func() { _ = opened.Close() }()
		raw, actual, err := readEditFileIdentity(opened, name, filepath.Join(directory, name))
		if err != nil {
			return err
		}
		if !sameUserModuleIdentity(expected, actual) {
			return errors.New("activation policy source changed during effective decoding")
		}
		document, err := parseTOMLDocument(raw, relative)
		if err != nil {
			return err
		}
		inventory.record(relative, document)
		flattenTOMLKeys("", document, observed)
		return v.MergeConfig(bytes.NewReader(raw))
	}
	if err := merge(root, "config.toml", "config.toml", snapshot.master); err != nil {
		return nil, nil, err
	}
	for _, name := range snapshot.moduleNames {
		identity := snapshot.modules[name]
		if name == userModuleName {
			identity = snapshot.user
		}
		if err := merge(filepath.Join(root, "modules"), name, "modules/"+name, identity); err != nil {
			return nil, nil, err
		}
	}
	if err := inventory.validate(); err != nil {
		return nil, nil, err
	}
	if err := rejectActivationPolicyEnvironment(); err != nil {
		return nil, nil, err
	}
	resolveModularSaaSAliasFromTOML(v, observed)
	if err := resolveOptionalModules(v); err != nil {
		return nil, nil, err
	}
	var modular ModularConfig
	if err := v.Unmarshal(&modular); err != nil {
		return nil, nil, err
	}
	// Refuse compatibility work rather than silently approving a normalized
	// interpretation. The original sources and previous global snapshot remain.
	probe := modular
	if len(neutralizeRetiredUnspecifiedWhitelistConfig(&probe)) != 0 {
		return nil, nil, errors.New("activation policy requires explicit recovery of retired unspecified whitelist entries before capture")
	}
	if err := validateConfig(&modular); err != nil {
		return nil, nil, err
	}
	candidate := mapModularToLegacy(&modular)
	if len(candidate.OperatorPolicy.Rules) != 0 {
		if snapshot.user == nil {
			return nil, nil, errors.New("activation operator policy has no captured user-module source")
		}
		candidate.operatorPolicySource = &operatorPolicySourceAttestation{
			modulesDir: filepath.Join(root, "modules"), identity: snapshot.user,
			policy: cloneOperatorPolicy(candidate.OperatorPolicy),
		}
	}
	return &modular, candidate, nil
}

func activationPolicyDigest(root string, snapshot *mergedConfigSnapshot, effective *ModularConfig) (string, error) {
	rootIdentity, err := moduleEditDirectoryFrom(snapshot.configRootInfo)
	if err != nil {
		return "", err
	}
	modulesIdentity, err := moduleEditDirectoryFrom(snapshot.modulesRootInfo)
	if err != nil {
		return "", err
	}
	master, err := moduleEditFileFrom(snapshot.master)
	if err != nil {
		return "", err
	}
	inputs := []moduleEditInput{{Path: "config.toml", File: master}}
	for _, name := range snapshot.moduleNames {
		identity := snapshot.modules[name]
		if name == userModuleName {
			identity = snapshot.user
		}
		file, err := moduleEditFileFrom(identity)
		if err != nil {
			return "", err
		}
		inputs = append(inputs, moduleEditInput{Path: "modules/" + name, File: file})
	}
	// The private encoding is hashed locally and is never part of Review.
	// Fixed field order and sorted input names make unchanged recapture stable.
	wire, err := json.Marshal(struct {
		Schema          string
		Environment     string
		Root            string
		RootIdentity    moduleEditDirectory
		ModulesIdentity moduleEditDirectory
		Inputs          []moduleEditInput
		Effective       *ModularConfig
	}{activationPolicySchema, activationPolicyEnvironment, root, rootIdentity, modulesIdentity, inputs, effective})
	if err != nil {
		return "", errors.New("cannot encode activation policy binding")
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}
