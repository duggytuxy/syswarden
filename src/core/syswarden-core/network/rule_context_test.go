package network

import (
	"testing"

	"syswarden-core/engine"
)

func TestLoggerRuleContextPreservesEnforcementAndRiskAttribution_SW_KPI_001(t *testing.T) {
	context := loggerRuleContext(&engine.Match{
		RuleID:                        "phpmyadmin",
		RiskCategory:                  "reconnaissance",
		Action:                        "ban",
		Threshold:                     1,
		RiskAttributionRuleID:         "owasp-a03-xss",
		RiskAttributionCategory:       "exploit",
		RiskAttributionAction:         "detect",
		RiskAttributionThreshold:      1,
		RiskAttributionMetricEligible: true,
		MetricEligible:                true,
	})
	if context.RuleID != "phpmyadmin" || context.RuleAction != "ban" ||
		context.RiskAttributionRuleID != "owasp-a03-xss" || context.RiskAttributionCategory != "exploit" ||
		context.RiskAttributionAction != "detect" || !context.RiskAttributionMetricEligible {
		t.Fatalf("logger rule context = %#v", context)
	}
}
