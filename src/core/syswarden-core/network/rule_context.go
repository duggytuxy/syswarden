package network

import (
	"syswarden-core/engine"
	"syswarden-core/logger"
)

func loggerRuleContext(match *engine.Match) logger.RuleContext {
	if match == nil {
		return logger.RuleContext{}
	}
	return logger.RuleContext{
		RuleID:                        match.RuleID,
		RiskCategory:                  match.RiskCategory,
		RuleAction:                    match.Action,
		EffectiveThreshold:            match.Threshold,
		EffectiveWindowSeconds:        match.Window,
		RiskAttributionRuleID:         match.RiskAttributionRuleID,
		RiskAttributionCategory:       match.RiskAttributionCategory,
		RiskAttributionAction:         match.RiskAttributionAction,
		RiskAttributionThreshold:      match.RiskAttributionThreshold,
		RiskAttributionWindowSeconds:  match.RiskAttributionWindow,
		RiskAttributionMetricEligible: match.RiskAttributionMetricEligible,
		SignatureCatalogVersion:       match.CatalogVersion,
		SignatureCatalogSHA256:        match.CatalogDigest,
		RiskModelVersion:              match.RiskModelVersion,
		MetricEligible:                match.MetricEligible,
		ObservedAt:                    match.ObservedAt,
		ObservationModel:              match.ObservationModel,
	}
}
