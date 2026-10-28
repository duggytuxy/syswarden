//go:build linux

package system

// The legacy mode is deliberately unchanged. A missing approval in a v1
// record is invalid, never an implicit request to preserve an inactive host.
const apkInactivePreservationMode = "inactive-preservation-v1"
const apkInactivePreparationSchema = "syswarden-apk-transition-preparation/v2"
const nativeInactiveBindingSchema = "syswarden-native-activation-binding-v2"

func (policy apkTransitionPolicyBinding) inactive() bool {
	return policy.LifecycleMode == apkInactivePreservationMode
}

func (policy apkTransitionPolicyBinding) valid() bool {
	if !validSHA256(policy.PolicySHA256) || !validSHA256(policy.HostSHA256) {
		return false
	}
	switch policy.LifecycleMode {
	case "":
		return validSHA256(policy.ApprovalSHA256) && policy.AbsenceSHA256 == ""
	case apkInactivePreservationMode:
		return policy.ApprovalSHA256 == "" && validSHA256(policy.AbsenceSHA256)
	default:
		return false
	}
}

func (policy apkTransitionPolicyBinding) preparationSchema() string {
	if policy.inactive() {
		return apkInactivePreparationSchema
	}
	return apkTransitionSchema
}

func (policy apkTransitionPolicyBinding) effectSchema() string {
	if policy.inactive() {
		return nativeInactiveBindingSchema
	}
	return nativeActivationBindingSchema
}

func (plan nativeActivationBindingPlan) validPublicationBinding(candidate NativeActivationCandidate) bool {
	if !plan.RuntimePolicy.valid() || plan.Schema != plan.RuntimePolicy.effectSchema() {
		return false
	}
	if plan.RuntimePolicy.inactive() {
		if plan.Format != packageFormatAPK || !candidate.publicationExclusion() {
			return false
		}
		// The exact protocol has one canonical descriptor for this source pair.
		// This checks the original record without adopting replacement binaries
		// as proof of the source's publication capability.
		raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(plan.Installed.CLI.SHA256, plan.Installed.Core.SHA256))
		if err != nil {
			return false
		}
		source, err := parseNativeActivationDescriptor(raw)
		return err == nil && source.publicationExclusion() && validSHA256(plan.SourcePublicationSHA256) && source.SHA256() == plan.SourcePublicationSHA256
	}
	return plan.SourcePublicationSHA256 == ""
}
