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

func sshAccessDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func newSSHAccessCommands(operations sshAccessOperations) []*cobra.Command {
	var commands []*cobra.Command
	for _, operation := range []string{"access-request", "access-issue", "access-record", "access-probe"} {
		var directoryPath, plan, enrollment, request, challenge, credentials, issuance, image string
		var lifetime int
		command := &cobra.Command{
			Use: operation,
			Short: map[string]string{
				"access-request": "Prepare a private SSH access request without issuance or networking",
				"access-issue":   "Issue one short-lived SSH challenge from independently approved inputs",
				"access-record":  "Record an independently signed access receipt without accepting migration",
				"access-probe":   "Authenticate approved SSH routes from an independent controller",
			}[operation],
			Long: "Exchange private SSH evidence through fixed files in an existing owner-only directory. " +
				"No configuration load, firewall recovery, policy publication or SSH reload is performed. " +
				"Access evidence does not establish policy consumption or completed migration. " +
				"Keep controller credentials on the independently administered controller. Failed issuance/delivery must not be retried by deleting records.",
			Args:         cobra.NoArgs,
			SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) (err error) {
				if flag := cmd.Flag("config"); flag != nil && flag.Changed {
					return errors.New("SSH access exchange does not accept --config")
				}
				digests := []string{plan, enrollment}
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
					result, err := operations.record(cmd.Context(), plan, enrollment, issuance, image, receipt)
					if err != nil {
						return fmt.Errorf("SSH receipt recording remains unverified (record_durable=%t, recovery_required=true): %w", result.RecordDurable, err)
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
					result, err := operations.prepare(cmd.Context(), plan, enrollment)
					if err != nil {
						return err
					}
					if len(result.Request) == 0 || !result.RecoveryRequired || sshAccessDigest(result.Request) != result.RequestSHA256 {
						return sshpolicy.ErrInventoryUnsafe
					}
					wire = result.Request
					summary["request_sha256"] = result.RequestSHA256
				case "access-issue":
					result, err := operations.issue(cmd.Context(), plan, enrollment, request, time.Duration(lifetime)*time.Second)
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
			command.Flags().StringVar(&enrollment, "enrollment-sha256", "", "Independently approved protected public enrollment SHA-256")
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
	case "syswarden ssh-policy access-request", "syswarden ssh-policy access-issue", "syswarden ssh-policy access-record", "syswarden ssh-policy access-probe":
		return true
	}
	return false
}
