package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"syswarden-cli/pkg/sshpolicy"

	"github.com/spf13/cobra"
)

const sshExchangeLimit = 1 << 20

type sshAccessDelivery struct {
	Schema              int    `json:"schema"`
	Request             []byte `json:"request"`
	Challenge           []byte `json:"challenge"`
	IssuanceSHA256      string `json:"issuance_sha256"`
	IssuanceImageSHA256 string `json:"issuance_image_sha256"`
}

type sshAccessOperations struct {
	prepare func(context.Context, string, string) (sshpolicy.AccessRequestPreview, error)
	issue   func(context.Context, string, string, string, time.Duration) (sshpolicy.AccessChallengePublication, error)
	record  func(context.Context, string, string, string, string, []byte) (sshpolicy.AccessReceiptPublication, error)
	probe   func(context.Context, []byte, []byte, string, string, []byte, func() error) ([]byte, error)
}

type sshRestoredAccessOperations struct {
	prepare func(context.Context, string, string, string) (sshpolicy.AccessRequestPreview, error)
	issue   func(context.Context, string, string, string, string, time.Duration) (sshpolicy.AccessChallengePublication, error)
	record  func(context.Context, string, string, string, string, string, []byte) (sshpolicy.AccessReceiptPublication, error)
	probe   func(context.Context, []byte, []byte, string, string, []byte, func() error) ([]byte, error)
}

func sshAccessDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func newSSHAccessCommands(operations sshAccessOperations) []*cobra.Command {
	return newSSHAccessExchangeCommands(sshRestoredAccessOperations{
		prepare: func(ctx context.Context, plan, _ string, enrollment string) (sshpolicy.AccessRequestPreview, error) {
			return operations.prepare(ctx, plan, enrollment)
		},
		issue: func(ctx context.Context, plan, _ string, enrollment, request string, lifetime time.Duration) (sshpolicy.AccessChallengePublication, error) {
			return operations.issue(ctx, plan, enrollment, request, lifetime)
		},
		record: func(ctx context.Context, plan, _ string, enrollment, issuance, image string, receipt []byte) (sshpolicy.AccessReceiptPublication, error) {
			return operations.record(ctx, plan, enrollment, issuance, image, receipt)
		},
		probe: operations.probe,
	}, false)
}

func newSSHRestoredAccessCommands(operations sshRestoredAccessOperations) []*cobra.Command {
	return newSSHAccessExchangeCommands(operations, true)
}

func newSSHAccessExchangeCommands(operations sshRestoredAccessOperations, restored bool) []*cobra.Command {
	var commands []*cobra.Command
	for _, operation := range []string{"access-request", "access-issue", "access-record", "access-probe"} {
		var directoryPath, plan, recovery, enrollment, request, challenge, credentials, issuance, image string
		var lifetime int
		name := operation
		short := map[string]string{
			"access-request": "Prepare a private SSH access request without issuance or networking",
			"access-issue":   "Issue one short-lived SSH challenge from independently approved inputs",
			"access-record":  "Record an independently signed access receipt without accepting migration",
			"access-probe":   "Authenticate approved SSH routes from an independent controller",
		}[operation]
		long := "Exchange private SSH evidence through fixed files in an existing owner-only directory. " +
			"No configuration load, firewall recovery, policy publication or SSH reload is performed. " +
			"Access evidence does not establish policy consumption or completed migration. " +
			"Keep controller credentials on the independently administered controller. Failed issuance/delivery must not be retried by deleting records."
		if restored {
			name = "restoration-" + operation
			short = map[string]string{
				"access-request": "Prepare a private restored SSH access request without issuance or networking",
				"access-issue":   "Issue one short-lived challenge for independently approved restored SSH access",
				"access-record":  "Record a restored SSH access receipt without accepting completed recovery",
				"access-probe":   "Authenticate approved restored SSH routes from an independent controller",
			}[operation]
			long = "Exchange private restored SSH access evidence through fixed files in an existing owner-only directory. " +
				"Target operations require independently approved migration and recovery plans plus a separate restoration controller enrollment. " +
				"No configuration load, firewall recovery, policy publication or SSH reload is performed. " +
				"Access evidence does not establish policy consumption or completed recovery. " +
				"Keep controller credentials on the independently administered controller. Failed issuance/delivery must not be retried by deleting records."
		}
		command := &cobra.Command{
			Use:          name,
			Short:        short,
			Long:         long,
			Args:         cobra.NoArgs,
			SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) (err error) {
				if flag := cmd.Flag("config"); flag != nil && flag.Changed {
					return errors.New("SSH access exchange does not accept --config")
				}
				digests := []string{plan, enrollment}
				if restored {
					digests = append(digests, recovery)
				}
				if operation == "access-issue" {
					digests = append(digests, request)
				}
				if operation == "access-record" {
					digests = append(digests, issuance, image)
				}
				if operation == "access-probe" {
					digests = []string{request, challenge, credentials}
				}
				for _, digest := range digests {
					if !sshRecoveryDigest.MatchString(digest) {
						return errors.New("SSH access exchange requires exact independently approved lowercase SHA-256 values")
					}
				}
				if operation == "access-issue" && (lifetime < 1 || lifetime > 300) {
					return errors.New("SSH challenge lifetime must be 1 to 300 seconds")
				}
				directory, err := openSSHExchangeDirectory(directoryPath)
				if err != nil {
					return err
				}
				defer func() { err = errors.Join(err, directory.close()) }()
				if operation == "access-record" {
					receipt, err := directory.read("receipt.json", 16<<10)
					if err != nil {
						return err
					}
					result, err := operations.record(cmd.Context(), plan, recovery, enrollment, issuance, image, receipt)
					if err != nil {
						return fmt.Errorf("SSH receipt recording remains unverified (record_durable=%t, recovery_required=true): %w", result.RecordDurable, err)
					}
					if restored && (!result.RecordDurable || !result.RecoveryRequired || !sshRecoveryDigest.MatchString(result.RecordSHA256)) {
						return sshpolicy.ErrInventoryUnsafe
					}
					return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
				}
				outputName := map[string]string{"access-request": "request.json", "access-issue": "delivery.json", "access-probe": "receipt.json"}[operation]
				output, err := directory.reserve(outputName)
				if err != nil {
					return err
				}
				defer func() { err = errors.Join(err, output.Close()) }()
				var wire []byte
				summary := map[string]any{"recovery_required": true}
				switch operation {
				case "access-request":
					result, err := operations.prepare(cmd.Context(), plan, recovery, enrollment)
					if err != nil {
						return err
					}
					if len(result.Request) == 0 || !result.RecoveryRequired || sshAccessDigest(result.Request) != result.RequestSHA256 {
						return sshpolicy.ErrInventoryUnsafe
					}
					wire = result.Request
					summary["request_sha256"] = result.RequestSHA256
				case "access-issue":
					result, err := operations.issue(cmd.Context(), plan, recovery, enrollment, request, time.Duration(lifetime)*time.Second)
					if err != nil {
						return fmt.Errorf("SSH challenge delivery remains unverified (issuance_durable=%t, recovery_required=true); preserve the journal and partial delivery: %w", result.IssuanceDurable, err)
					}
					if !result.IssuanceDurable || !result.RecoveryRequired || sshAccessDigest(result.Request) != request || len(result.Challenge) == 0 ||
						!sshRecoveryDigest.MatchString(result.IssuanceSHA256) || !sshRecoveryDigest.MatchString(result.IssuanceImageSHA256) {
						return sshpolicy.ErrInventoryUnsafe
					}
					wire, err = json.Marshal(sshAccessDelivery{1, result.Request, result.Challenge, result.IssuanceSHA256, result.IssuanceImageSHA256})
					if err != nil {
						return err
					}
					summary["request_sha256"], summary["challenge_sha256"] = request, sshAccessDigest(result.Challenge)
					summary["issuance_sha256"], summary["issuance_image_sha256"] = result.IssuanceSHA256, result.IssuanceImageSHA256
				case "access-probe":
					wire, err = runSSHControllerProbe(cmd.Context(), directory, request, challenge, credentials, operations.probe)
					if err != nil {
						return err
					}
				}
				if err := directory.publish(output, outputName, wire); err != nil {
					return err
				}
				summary["output_sha256"] = sshAccessDigest(wire)
				return json.NewEncoder(cmd.OutOrStdout()).Encode(summary)
			},
		}
		command.Flags().StringVar(&directoryPath, "exchange-dir", "", "Existing absolute private directory, mode 0700; fixed files use mode 0600")
		_ = command.MarkFlagRequired("exchange-dir")
		if operation != "access-probe" {
			command.Flags().StringVar(&plan, "plan-sha256", "", "Independently approved original migration plan SHA-256")
			enrollmentUsage := "Independently approved protected public enrollment SHA-256"
			if restored {
				enrollmentUsage = "Independently approved protected restoration controller enrollment SHA-256"
				command.Flags().StringVar(&recovery, "recovery-sha256", "", "Independently approved recovery plan SHA-256")
				_ = command.MarkFlagRequired("recovery-sha256")
			}
			command.Flags().StringVar(&enrollment, "enrollment-sha256", "", enrollmentUsage)
			_ = command.MarkFlagRequired("plan-sha256")
			_ = command.MarkFlagRequired("enrollment-sha256")
		}
		if operation == "access-issue" || operation == "access-probe" {
			command.Flags().StringVar(&request, "request-sha256", "", "Independently reviewed complete request SHA-256")
			_ = command.MarkFlagRequired("request-sha256")
		}
		if operation == "access-issue" {
			command.Flags().IntVar(&lifetime, "lifetime-seconds", 180, "Whole-second challenge validity from 1 to 300")
		}
		if operation == "access-record" {
			command.Flags().StringVar(&issuance, "issuance-sha256", "", "Independently approved durable issuance SHA-256")
			command.Flags().StringVar(&image, "issuance-image-sha256", "", "Independently approved original issuance image SHA-256")
			_ = command.MarkFlagRequired("issuance-sha256")
			_ = command.MarkFlagRequired("issuance-image-sha256")
		}
		if operation == "access-probe" {
			command.Flags().StringVar(&challenge, "challenge-sha256", "", "Independently approved exact challenge SHA-256")
			command.Flags().StringVar(&credentials, "credentials-sha256", "", "Independently approved controller-local credentials file SHA-256")
			_ = command.MarkFlagRequired("challenge-sha256")
			_ = command.MarkFlagRequired("credentials-sha256")
		}
		commands = append(commands, command)
	}
	return commands
}

func newSSHRestoredAccessInspectionCommand(inspect func(context.Context, string, string, string, string, string, string) (sshpolicy.RestoredAccessInspection, error)) *cobra.Command {
	var plan, recovery, enrollment, issuance, image, record string
	command := &cobra.Command{
		Use:   "restoration-access-inspect",
		Short: "Inspect approved restored SSH access records without accepting completed recovery",
		Long: "Inspect protected restoration access issuance and, when independently approved, its recorded receipt. " +
			"This command does not write or repair the journal, load general configuration, recover firewall state or reload SSH. " +
			"Observed records do not establish durability, current access, policy consumption or completed recovery.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if flag := cmd.Flag("config"); flag != nil && flag.Changed {
				return errors.New("SSH restoration access inspection does not accept --config")
			}
			for _, digest := range []string{plan, recovery, enrollment, issuance, image} {
				if !sshRecoveryDigest.MatchString(digest) {
					return errors.New("SSH restoration access inspection requires exact independently approved lowercase SHA-256 values")
				}
			}
			if cmd.Flags().Changed("record-sha256") && !sshRecoveryDigest.MatchString(record) {
				return errors.New("SSH restoration receipt inspection requires an exact independently approved lowercase SHA-256 value")
			}
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			result, err := inspect(cmd.Context(), plan, recovery, enrollment, issuance, image, record)
			if err = errors.Join(err, cmd.Context().Err()); err != nil {
				return err
			}
			if !result.RecoveryRequired || !result.IssuanceObserved || result.IssuanceSHA256 != issuance ||
				result.IssuanceImageSHA256 != image || result.RecordSHA256 != record || result.ReceiptObserved != (record != "") {
				return sshpolicy.ErrInventoryUnsafe
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		},
	}
	for _, flag := range []struct {
		name, usage string
		target      *string
	}{
		{"plan-sha256", "Independently approved original migration plan SHA-256", &plan},
		{"recovery-sha256", "Independently approved recovery plan SHA-256", &recovery},
		{"enrollment-sha256", "Independently approved protected restoration controller enrollment SHA-256", &enrollment},
		{"issuance-sha256", "Independently approved durable issuance SHA-256", &issuance},
		{"issuance-image-sha256", "Independently approved original issuance image SHA-256", &image},
	} {
		command.Flags().StringVar(flag.target, flag.name, "", flag.usage)
		_ = command.MarkFlagRequired(flag.name)
	}
	command.Flags().StringVar(&record, "record-sha256", "", "Independently approved receipt record SHA-256; omit only for issuance without a recorded receipt")
	return command
}

func runSSHControllerProbe(ctx context.Context, directory *sshExchangeDirectory, requestSHA, challengeSHA, secretSHA string,
	probe func(context.Context, []byte, []byte, string, string, []byte, func() error) ([]byte, error)) ([]byte, error) {
	deliveryWire, err := directory.read("delivery.json", sshExchangeLimit)
	if err != nil {
		return nil, err
	}
	var delivery sshAccessDelivery
	if err := json.Unmarshal(deliveryWire, &delivery); err != nil {
		return nil, sshpolicy.ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(delivery)
	if err != nil || !bytes.Equal(canonical, deliveryWire) || delivery.Schema != 1 ||
		sshAccessDigest(delivery.Request) != requestSHA || sshAccessDigest(delivery.Challenge) != challengeSHA ||
		!sshRecoveryDigest.MatchString(delivery.IssuanceSHA256) || !sshRecoveryDigest.MatchString(delivery.IssuanceImageSHA256) {
		return nil, sshpolicy.ErrInventoryUnsafe
	}
	secret, err := directory.read("credentials.json", sshExchangeLimit)
	defer clear(secret)
	if err != nil || sshAccessDigest(secret) != secretSHA {
		return nil, sshpolicy.ErrInventoryUnsafe
	}
	guard := func() error {
		return errors.Join(ctx.Err(), directory.unchanged("delivery.json", deliveryWire, sshExchangeLimit), directory.unchanged("credentials.json", secret, sshExchangeLimit))
	}
	if err := guard(); err != nil {
		return nil, err
	}
	receipt, err := probe(ctx, delivery.Request, delivery.Challenge, requestSHA, challengeSHA, secret, guard)
	if err != nil {
		return nil, errors.New("SSH controller probe refused; no receipt published")
	}
	if len(receipt) == 0 || len(receipt) > 16<<10 {
		return nil, sshpolicy.ErrInventoryUnsafe
	}
	if err := guard(); err != nil {
		return nil, err
	}
	return receipt, nil
}

func sshAccessExchangeCommand(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	switch cmd.CommandPath() {
	case "syswarden ssh-policy access-request", "syswarden ssh-policy access-issue", "syswarden ssh-policy access-record", "syswarden ssh-policy access-probe",
		"syswarden ssh-policy restoration-access-request", "syswarden ssh-policy restoration-access-issue", "syswarden ssh-policy restoration-access-record", "syswarden ssh-policy restoration-access-probe":
		return true
	}
	return false
}

func sshAccessControllerCommand(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	switch cmd.CommandPath() {
	case "syswarden ssh-policy access-probe", "syswarden ssh-policy restoration-access-probe":
		return true
	}
	return false
}
