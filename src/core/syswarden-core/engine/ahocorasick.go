package engine

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	goahocorasick "github.com/duggytuxy/ahocorasick"
)

type RuleDef struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	Pattern            string   `json:"pattern,omitempty"`
	Patterns           []string `json:"patterns,omitempty"`
	Service            string   `json:"service"`
	MatchScope         string   `json:"match_scope,omitempty"`
	Action             string   `json:"action,omitempty"` // "ban" (default), "detect", or "track"
	Threshold          int      `json:"threshold,omitempty"`
	Window             int      `json:"window,omitempty"`
	TrustedHostCapture bool     `json:"trusted_host_capture,omitempty"`
	RiskCategory       string   `json:"-"`
	MetricEligible     bool     `json:"-"`
}

type Config struct {
	CatalogVersion      string              `json:"catalog_version,omitempty"`
	RiskModelVersion    string              `json:"risk_model_version,omitempty"`
	RiskCategories      map[string][]string `json:"risk_categories,omitempty"`
	MetricExcludedRules []string            `json:"metric_excluded_rules,omitempty"`
	Rules               []RuleDef           `json:"rules"`
}

type Engine struct {
	ahoMachine         *goahocorasick.Automaton
	patternToRule      map[string][]RuleDef
	regexRules         []compiledRegex
	requestTargetRules bool

	ahoCount             int
	defaultThreshold     int
	defaultWindow        int
	tracker              sync.Map
	trackerMu            sync.Mutex
	ingressMu            sync.Mutex
	ingressPending       map[[sha256.Size]byte]*ingressPair
	ingressOrder         *list.List
	ingressCount         int
	ingressNow           func() time.Time
	ingressWindow        time.Duration
	ingressDegradedUntil time.Time
	catalogVersion       string
	catalogDigest        string
	riskModelVersion     string
}

const (
	matchScopeRecord        = "record"
	matchScopeRequestTarget = "request-target"
	maxRequestTargetBytes   = 16 * 1024
	maxScopedRecordBytes    = 1 << 20
)

// IngressSource identifies an independent delivery path for the same physical
// log record. It is intentionally limited to the two collectors owned by the
// core so duplicates can be paired across collectors without suppressing
// repeated records delivered by one collector.
type IngressSource uint8

const (
	IngressSourceUDS IngressSource = iota + 1
	IngressSourceDirect
	ingressDedupWindow  = 5 * time.Second
	ingressPendingLimit = 16 * 1024
	// IngressCorrelationModel names the bounded cross-collector correlation
	// method persisted with each retained network observation.
	IngressCorrelationModel = "collector-content-window-v1"
	// IngressCorrelationDegradedModel marks observations retained while a
	// bounded cache eviction can no longer guarantee complete pairing.
	IngressCorrelationDegradedModel = "collector-content-window-degraded-v1"
)

type ingressPair struct {
	uds    ingressQueue
	direct ingressQueue
}

type ingressObservation struct {
	fingerprint [sha256.Size]byte
	source      IngressSource
	observedAt  time.Time
	orderEntry  *list.Element
}

type ingressQueue struct {
	items []*ingressObservation
	head  int
}

func (queue *ingressQueue) len() int {
	return len(queue.items) - queue.head
}

func (queue *ingressQueue) push(observation *ingressObservation) {
	queue.items = append(queue.items, observation)
}

func (queue *ingressQueue) front() *ingressObservation {
	if queue.len() == 0 {
		return nil
	}
	return queue.items[queue.head]
}

func (queue *ingressQueue) popFront() *ingressObservation {
	observation := queue.front()
	if observation == nil {
		return nil
	}
	queue.items[queue.head] = nil
	queue.head++
	if queue.head >= 64 && queue.head*2 >= len(queue.items) {
		queue.items = append([]*ingressObservation(nil), queue.items[queue.head:]...)
		queue.head = 0
	}
	return observation
}

type compiledRegex struct {
	def RuleDef
	re  *regexp.Regexp
}

type Match struct {
	RuleID                        string
	Payload                       string
	Service                       string
	Action                        string
	Threshold                     int
	Window                        int
	RiskCategory                  string
	RiskAttributionRuleID         string
	RiskAttributionCategory       string
	RiskAttributionAction         string
	RiskAttributionThreshold      int
	RiskAttributionWindow         int
	RiskAttributionMetricEligible bool
	CatalogVersion                string
	CatalogDigest                 string
	RiskModelVersion              string
	MetricEligible                bool
	ObservedAt                    time.Time
	ObservationModel              string
	Host                          netip.Addr
}

var supportedRiskCategories = map[string]struct{}{
	"exploit":           {},
	"brute_force":       {},
	"reconnaissance":    {},
	"denial_of_service": {},
	"abuse":             {},
}

func normalizeAndValidateRules(config *Config, defaultThreshold, defaultWindow int) error {
	if config == nil || len(config.Rules) == 0 {
		return fmt.Errorf("catalog has no rules")
	}
	hasRiskCatalog := len(config.RiskCategories) > 0
	if hasRiskCatalog {
		if config.CatalogVersion == "" || config.RiskModelVersion == "" {
			return fmt.Errorf("risk catalog and model versions are required")
		}
		if config.RiskModelVersion != "sw-risk-v1" {
			return fmt.Errorf("unsupported risk model %q", config.RiskModelVersion)
		}
		if len(config.RiskCategories) != len(supportedRiskCategories) {
			return fmt.Errorf("risk catalog must define exactly %d categories", len(supportedRiskCategories))
		}
	} else if config.CatalogVersion != "" || config.RiskModelVersion != "" || len(config.MetricExcludedRules) > 0 {
		return fmt.Errorf("catalog metadata requires an exhaustive risk category mapping")
	}

	categoryByRule := make(map[string]string, len(config.Rules))
	for category, ruleIDs := range config.RiskCategories {
		if _, ok := supportedRiskCategories[category]; !ok {
			return fmt.Errorf("unsupported risk category %q", category)
		}
		if len(ruleIDs) == 0 {
			return fmt.Errorf("risk category %q is empty", category)
		}
		for _, ruleID := range ruleIDs {
			if ruleID == "" {
				return fmt.Errorf("risk category %q contains an empty rule ID", category)
			}
			if previous, exists := categoryByRule[ruleID]; exists {
				return fmt.Errorf("rule %q is classified as both %q and %q", ruleID, previous, category)
			}
			categoryByRule[ruleID] = category
		}
	}

	excluded := make(map[string]struct{}, len(config.MetricExcludedRules))
	for _, ruleID := range config.MetricExcludedRules {
		if ruleID == "" {
			return fmt.Errorf("metric exclusion contains an empty rule ID")
		}
		if _, duplicate := excluded[ruleID]; duplicate {
			return fmt.Errorf("metric exclusion for rule %q is duplicated", ruleID)
		}
		excluded[ruleID] = struct{}{}
	}

	seen := make(map[string]struct{}, len(config.Rules))
	for index := range config.Rules {
		rule := &config.Rules[index]
		if rule.ID == "" {
			return fmt.Errorf("rule at index %d has an empty ID", index)
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return fmt.Errorf("rule ID %q is duplicated", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.MatchScope == "" {
			rule.MatchScope = matchScopeRecord
		}
		switch rule.MatchScope {
		case matchScopeRecord, matchScopeRequestTarget:
		default:
			return fmt.Errorf("rule %q has unsupported match scope %q", rule.ID, rule.MatchScope)
		}
		if rule.MatchScope == matchScopeRequestTarget && rule.TrustedHostCapture {
			return fmt.Errorf("request-target rule %q cannot trust a host capture", rule.ID)
		}
		switch rule.Type {
		case "regex", "aho-corasick":
		default:
			return fmt.Errorf("rule %q has unsupported type %q", rule.ID, rule.Type)
		}
		if rule.Action == "" {
			rule.Action = "ban"
		}
		switch rule.Action {
		case "ban", "detect", "track":
		default:
			return fmt.Errorf("rule %q has unsupported action %q", rule.ID, rule.Action)
		}
		if rule.Threshold < 0 || rule.Window < 0 {
			return fmt.Errorf("rule %q has a negative threshold or window", rule.ID)
		}
		if rule.Action == "track" {
			if rule.Threshold == 0 {
				rule.Threshold = defaultThreshold
			}
			if rule.Window == 0 {
				rule.Window = defaultWindow
			}
		} else {
			if rule.Threshold != 0 || rule.Window != 0 {
				return fmt.Errorf("immediate rule %q must not define a threshold or window", rule.ID)
			}
			rule.Threshold = 1
			rule.Window = 0
		}
		rule.MetricEligible = true
		if _, omit := excluded[rule.ID]; omit {
			rule.MetricEligible = false
		}
		if hasRiskCatalog {
			category, classified := categoryByRule[rule.ID]
			if !classified {
				return fmt.Errorf("rule %q has no risk category", rule.ID)
			}
			rule.RiskCategory = category
		} else {
			rule.RiskCategory = "unknown"
		}
	}
	for ruleID := range categoryByRule {
		if _, exists := seen[ruleID]; !exists {
			return fmt.Errorf("risk category references unknown rule %q", ruleID)
		}
	}
	for ruleID := range excluded {
		if _, exists := seen[ruleID]; !exists {
			return fmt.Errorf("metric exclusion references unknown rule %q", ruleID)
		}
	}
	return nil
}

func NewEngine(configFile string, defaultThreshold, defaultWindow int) (*Engine, error) {
	data, err := os.ReadFile(configFile) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read signatures: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse signatures JSON: %w", err)
	}
	if defaultThreshold <= 0 || defaultWindow <= 0 {
		return nil, fmt.Errorf("default threshold and window must be positive")
	}
	if err := normalizeAndValidateRules(&config, defaultThreshold, defaultWindow); err != nil {
		return nil, fmt.Errorf("invalid signatures catalog: %w", err)
	}
	catalogChecksum := sha256.Sum256(data)

	e := &Engine{
		patternToRule:    make(map[string][]RuleDef),
		defaultThreshold: defaultThreshold,
		defaultWindow:    defaultWindow,
		ingressPending:   make(map[[sha256.Size]byte]*ingressPair),
		ingressOrder:     list.New(),
		ingressNow:       time.Now,
		ingressWindow:    ingressDedupWindow,
		catalogVersion:   config.CatalogVersion,
		catalogDigest:    hex.EncodeToString(catalogChecksum[:]),
		riskModelVersion: config.RiskModelVersion,
	}

	ahoBuilder := goahocorasick.NewBuilder()

	for _, rule := range config.Rules {
		if rule.MatchScope == matchScopeRequestTarget {
			e.requestTargetRules = true
		}
		switch rule.Type {
		case "aho-corasick":
			if rule.TrustedHostCapture {
				return nil, fmt.Errorf("rule %s cannot trust a host capture without a regex placeholder", rule.ID)
			}
			for _, pat := range rule.Patterns {
				ahoBuilder.AddPattern([]byte(pat))
				e.patternToRule[pat] = append(e.patternToRule[pat], rule)
				e.ahoCount++
			}
		case "regex":
			if rule.TrustedHostCapture && (strings.Count(rule.Pattern, "<HOST>") != 1 || !strings.HasPrefix(rule.Pattern, "^")) {
				return nil, fmt.Errorf("rule %s must be anchored and contain exactly one <HOST> placeholder for a trusted capture", rule.ID)
			}
			strictHostRegex := `(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+:[a-fA-F0-9:]+)`
			safePattern := strings.ReplaceAll(rule.Pattern, "<HOST>", strictHostRegex)
			re, err := regexp.Compile("(?i)" + safePattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex for rule %s: %w", rule.ID, err)
			}
			if rule.TrustedHostCapture {
				hostCaptureCount := 0
				for _, name := range re.SubexpNames() {
					if name == "host" {
						hostCaptureCount++
					}
				}
				if hostCaptureCount != 1 {
					return nil, fmt.Errorf("rule %s must compile to exactly one trusted host capture", rule.ID)
				}
			}
			e.regexRules = append(e.regexRules, compiledRegex{def: rule, re: re})
		}
	}

	if e.ahoCount > 0 {
		machine, err := ahoBuilder.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build aho-corasick machine: %w", err)
		}
		e.ahoMachine = machine
	}

	// Start garbage collector for tracker
	go e.GarbageCollector()

	return e, nil
}

func (e *Engine) RuleCount() int {
	return e.ahoCount + len(e.regexRules)
}

func (e *Engine) Scan(logLine string) *Match {
	structuralHost := authoritativeRecordHost(logLine)
	requestTarget, hasRequestTarget := "", false
	if e.requestTargetRules {
		requestTarget, hasRequestTarget = extractRequestTarget(logLine)
	}
	type regexCandidate struct {
		match *Match
		start int
	}
	regexCandidates := make([]regexCandidate, 0, len(e.regexRules))
	addRegexCandidate := func(rr compiledRegex, content string) {
		indexes := rr.re.FindStringSubmatchIndex(content)
		if indexes == nil {
			return
		}
		hostIdx := rr.re.SubexpIndex("host")
		host := structuralHost
		if !host.IsValid() && hostIdx >= 0 && rr.def.TrustedHostCapture {
			indexOffset := 2 * hostIdx
			if indexOffset+1 >= len(indexes) || indexes[indexOffset] < 0 || indexes[indexOffset+1] < 0 {
				return
			}
			var ok bool
			host, ok = canonicalSourceAddr(content[indexes[indexOffset]:indexes[indexOffset+1]])
			if !ok {
				return
			}
		}

		regexCandidates = append(regexCandidates, regexCandidate{match: &Match{
			RuleID:           rr.def.ID,
			Payload:          logLine,
			Service:          rr.def.Service,
			Action:           rr.def.Action,
			Threshold:        rr.def.Threshold,
			Window:           rr.def.Window,
			RiskCategory:     rr.def.RiskCategory,
			CatalogVersion:   e.catalogVersion,
			CatalogDigest:    e.catalogDigest,
			RiskModelVersion: e.riskModelVersion,
			MetricEligible:   rr.def.MetricEligible,
			Host:             host,
		}, start: indexes[0]})
	}
	for _, rr := range e.regexRules {
		if rr.def.MatchScope == matchScopeRecord {
			addRegexCandidate(rr, logLine)
			continue
		}
		if !hasRequestTarget {
			continue
		}
		addRegexCandidate(rr, requestTarget)
		decodedTarget, err := url.QueryUnescape(requestTarget)
		if err == nil && decodedTarget != requestTarget {
			addRegexCandidate(rr, decodedTarget)
		}
	}

	// A syslog record does not have a structural leading or JSON address. In
	// that case, bind the record to the host captured by the earliest matching
	// signature. Later attacker-controlled text may match another service's
	// signature, but it cannot replace that record-level authority.
	var capturedAuthority netip.Addr
	if !structuralHost.IsValid() {
		authorityStart := len(logLine) + 1
		for _, candidate := range regexCandidates {
			if candidate.match.Host.IsValid() && candidate.start < authorityStart {
				capturedAuthority = candidate.match.Host
				authorityStart = candidate.start
			}
		}
	}

	var best *Match
	var riskAttribution *Match
	consider := func(candidate *Match) {
		best = preferHigherImpactMatch(best, candidate)
		riskAttribution = preferHigherRiskMatch(riskAttribution, candidate)
	}
	for _, candidate := range regexCandidates {
		if capturedAuthority.IsValid() && candidate.match.Host.IsValid() && candidate.match.Host != capturedAuthority {
			continue
		}
		consider(candidate.match)
	}

	if e.ahoMachine != nil {
		addMatches := func(content []byte, scope string) {
			for _, ahoMatch := range e.ahoMachine.FindAllOverlapping(content) {
				for _, rule := range e.patternToRule[string(e.ahoMachine.Pattern(ahoMatch.PatternID))] {
					if rule.MatchScope != scope {
						continue
					}
					consider(&Match{
						RuleID:           rule.ID,
						Payload:          logLine,
						Service:          rule.Service,
						Action:           rule.Action,
						Threshold:        rule.Threshold,
						Window:           rule.Window,
						RiskCategory:     rule.RiskCategory,
						CatalogVersion:   e.catalogVersion,
						CatalogDigest:    e.catalogDigest,
						RiskModelVersion: e.riskModelVersion,
						MetricEligible:   rule.MetricEligible,
						Host:             structuralHost,
					})
				}
			}
		}

		addMatches([]byte(logLine), matchScopeRecord)
		decodedLine, err := url.QueryUnescape(logLine)
		if err == nil && decodedLine != logLine {
			addMatches([]byte(decodedLine), matchScopeRecord)
		}
		if hasRequestTarget {
			addMatches([]byte(requestTarget), matchScopeRequestTarget)
			decodedTarget, err := url.QueryUnescape(requestTarget)
			if err == nil && decodedTarget != requestTarget {
				addMatches([]byte(decodedTarget), matchScopeRequestTarget)
			}
		}
	}
	if best != nil && riskAttribution != nil && riskAttribution.RuleID != best.RuleID {
		best.RiskAttributionRuleID = riskAttribution.RuleID
		best.RiskAttributionCategory = riskAttribution.RiskCategory
		best.RiskAttributionAction = riskAttribution.Action
		best.RiskAttributionThreshold = riskAttribution.Threshold
		best.RiskAttributionWindow = riskAttribution.Window
		best.RiskAttributionMetricEligible = riskAttribution.MetricEligible
	}

	return best
}

// ScanIngress scans one record and suppresses only the paired copy delivered
// by the other core-owned collector. Identical records seen repeatedly through
// one collector remain distinct attempts and therefore keep their real impact
// on threshold evaluation and telemetry.
func (e *Engine) ScanIngress(source IngressSource, logLine string) *Match {
	transportNormalized := strings.TrimSuffix(logLine, "\n")
	transportNormalized = strings.TrimSuffix(transportNormalized, "\r")
	match := e.Scan(transportNormalized)
	if match == nil || !match.Host.IsValid() {
		return match
	}
	if source != IngressSourceUDS && source != IngressSourceDirect {
		match.ObservedAt = time.Now().UTC()
		return match
	}
	if !e.acceptIngress(source, transportNormalized, match) {
		return nil
	}
	return match
}

func (e *Engine) acceptIngress(source IngressSource, logLine string, match *Match) bool {
	canonical := logLine + "\x00" + match.RuleID + "\x00" + match.Host.String()
	fingerprint := sha256.Sum256([]byte(canonical))

	e.ingressMu.Lock()
	defer e.ingressMu.Unlock()
	now := e.ingressNow()

	e.expireIngressObservations(now)
	match.ObservedAt = now.UTC()
	pair := e.ingressPending[fingerprint]
	if pair == nil {
		pair = &ingressPair{}
		e.ingressPending[fingerprint] = pair
	}

	switch source {
	case IngressSourceUDS:
		if observation := pair.direct.popFront(); observation != nil {
			e.removeIngressObservation(observation, false)
			e.storeIngressPair(fingerprint, pair)
			return false
		}
	case IngressSourceDirect:
		if observation := pair.uds.popFront(); observation != nil {
			e.removeIngressObservation(observation, false)
			e.storeIngressPair(fingerprint, pair)
			return false
		}
	}

	e.reserveIngressObservation(now)
	match.ObservationModel = IngressCorrelationModel
	if !e.ingressDegradedUntil.IsZero() && !now.After(e.ingressDegradedUntil) {
		match.ObservationModel = IngressCorrelationDegradedModel
	}
	observation := &ingressObservation{
		fingerprint: fingerprint,
		source:      source,
		observedAt:  now,
	}
	observation.orderEntry = e.ingressOrder.PushBack(observation)
	if source == IngressSourceUDS {
		pair.uds.push(observation)
	} else {
		pair.direct.push(observation)
	}
	e.ingressCount++
	// reserveIngressObservation may have evicted the final prior observation
	// for this fingerprint and removed its map entry. Re-publish the pair after
	// inserting the new record so its counterpart cannot become orphaned.
	e.ingressPending[fingerprint] = pair
	return true
}

func (e *Engine) storeIngressPair(fingerprint [sha256.Size]byte, pair *ingressPair) {
	if pair == nil || pair.uds.len() == 0 && pair.direct.len() == 0 {
		delete(e.ingressPending, fingerprint)
	}
}

func (e *Engine) expireIngressObservations(now time.Time) {
	for e.ingressOrder.Len() > 0 {
		observation := e.ingressOrder.Front().Value.(*ingressObservation)
		age := now.Sub(observation.observedAt)
		// time.Now carries a monotonic component in production. If a test clock
		// or wall clock adjustment nevertheless moves backwards, retain the
		// record instead of creating a duplicate-counting window.
		if age <= e.ingressWindow {
			break
		}
		e.removeIngressObservation(observation, true)
	}
}

func (e *Engine) reserveIngressObservation(now time.Time) {
	evicted := false
	for e.ingressCount >= ingressPendingLimit && e.ingressOrder.Len() > 0 {
		observation := e.ingressOrder.Front().Value.(*ingressObservation)
		e.removeIngressObservation(observation, true)
		evicted = true
	}
	if evicted {
		e.ingressDegradedUntil = now.Add(e.ingressWindow)
	}
}

// removeIngressObservation removes one active observation in amortized O(1),
// strictly bounded by ingressPendingLimit. When the caller already popped the
// per-source queue, removeFromPair must be false.
func (e *Engine) removeIngressObservation(observation *ingressObservation, removeFromPair bool) {
	if observation == nil || observation.orderEntry == nil {
		return
	}
	if removeFromPair {
		pair := e.ingressPending[observation.fingerprint]
		if pair != nil {
			var removed *ingressObservation
			if observation.source == IngressSourceUDS {
				removed = pair.uds.popFront()
			} else {
				removed = pair.direct.popFront()
			}
			if removed != observation {
				panic("engine ingress queue order invariant violated")
			}
			e.storeIngressPair(observation.fingerprint, pair)
		}
	}
	e.ingressOrder.Remove(observation.orderEntry)
	observation.orderEntry = nil
	e.ingressCount--
	if e.ingressCount < 0 {
		panic("engine ingress observation count invariant violated")
	}
}

func preferHigherImpactMatch(current, candidate *Match) *Match {
	if current == nil {
		return candidate
	}
	if candidate.Host.IsValid() != current.Host.IsValid() {
		if candidate.Host.IsValid() {
			return candidate
		}
		return current
	}
	if matchImpact(candidate.Action) > matchImpact(current.Action) {
		return candidate
	}
	return current
}

func preferHigherRiskMatch(current, candidate *Match) *Match {
	if current == nil {
		return candidate
	}
	if candidate.Host.IsValid() != current.Host.IsValid() {
		if candidate.Host.IsValid() {
			return candidate
		}
		return current
	}
	if candidate.MetricEligible != current.MetricEligible {
		if candidate.MetricEligible {
			return candidate
		}
		return current
	}
	candidateScore := matchInitialRiskScore(candidate)
	currentScore := matchInitialRiskScore(current)
	if candidateScore != currentScore {
		if candidateScore > currentScore {
			return candidate
		}
		return current
	}
	if matchCategoryBase(candidate.RiskCategory) != matchCategoryBase(current.RiskCategory) {
		if matchCategoryBase(candidate.RiskCategory) > matchCategoryBase(current.RiskCategory) {
			return candidate
		}
		return current
	}
	if matchImpact(candidate.Action) > matchImpact(current.Action) {
		return candidate
	}
	return current
}

// matchInitialRiskScore mirrors the sw-risk-v1 score for one physical
// observation. Selecting the event with the highest evidence-based score
// prevents a generic track rule from hiding a simultaneous exploit signature.
func matchInitialRiskScore(match *Match) int {
	if match == nil {
		return -1
	}
	score := matchCategoryBase(match.RiskCategory)
	switch match.Action {
	case "ban":
		score += 30
	case "detect":
		score += 20
	case "track":
		threshold := match.Threshold
		if threshold <= 1 {
			score += 40
		} else {
			score += (40 + threshold - 1) / threshold
		}
	}
	if score > 100 {
		return 100
	}
	return score
}

func matchCategoryBase(category string) int {
	switch category {
	case "exploit":
		return 50
	case "denial_of_service":
		return 40
	case "brute_force", "reconnaissance":
		return 20
	case "abuse":
		return 10
	default:
		return 0
	}
}

func matchImpact(action string) int {
	switch action {
	case "detect":
		return 1
	case "track":
		return 2
	default:
		return 3
	}
}

func authoritativeRecordHost(logLine string) netip.Addr {
	value := ExtractIP(logLine)
	if value == "" {
		return netip.Addr{}
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
}

var jsonRequestTargetFieldNames = map[string]struct{}{
	"path":           {},
	"uri":            {},
	"request_uri":    {},
	"requestURI":     {},
	"RequestURI":     {},
	"RequestPath":    {},
	"request_target": {},
	"requestTarget":  {},
	"RequestTarget":  {},
}

var jsonRequestLineFieldNames = map[string]struct{}{
	"request":      {},
	"request_line": {},
	"RequestLine":  {},
}

// extractRequestTarget returns only an unambiguous HTTP request-target. It is
// intentionally strict: scoped immediate-ban rules must not fall back to the
// complete record when a supported access-log record is malformed or lacks a
// target.
func extractRequestTarget(logLine string) (string, bool) {
	if len(logLine) == 0 || len(logLine) > maxScopedRecordBytes {
		return "", false
	}
	trimmed := strings.TrimSpace(logLine)
	if trimmed == "" {
		return "", false
	}
	if strings.HasPrefix(trimmed, "{") {
		return extractTopLevelJSONRequestTarget(trimmed)
	}
	if target, ok := extractCommonAccessLogRequestTarget(trimmed); ok {
		return target, true
	}
	return extractPrefixedRequestTarget(trimmed)
}

// extractCommonAccessLogRequestTarget accepts the Apache/Nginx common and
// combined access-log prefix:
//
//	host ident user [timestamp] "METHOD request-target HTTP/version" status bytes
//
// The request field is consumed at its structural position, so later quoted
// Referer and User-Agent fields can never be mistaken for request data.
func extractCommonAccessLogRequestTarget(logLine string) (string, bool) {
	position := 0
	host, ok := consumeAccessLogToken(logLine, &position)
	if !ok {
		return "", false
	}
	if _, valid := canonicalSourceAddr(host); !valid {
		return "", false
	}
	if _, ok := consumeAccessLogToken(logLine, &position); !ok {
		return "", false
	}
	if _, ok := consumeAccessLogToken(logLine, &position); !ok {
		return "", false
	}
	consumeAccessLogWhitespace(logLine, &position)
	if position >= len(logLine) || logLine[position] != '[' {
		return "", false
	}
	timestampEnd := strings.IndexByte(logLine[position+1:], ']')
	if timestampEnd < 0 || timestampEnd > 128 {
		return "", false
	}
	position += timestampEnd + 2
	if !consumeAccessLogWhitespace(logLine, &position) || position >= len(logLine) || logLine[position] != '"' {
		return "", false
	}
	position++
	requestEnd := strings.IndexByte(logLine[position:], '"')
	if requestEnd < 0 || requestEnd > maxRequestTargetBytes+64 {
		return "", false
	}
	requestLine := logLine[position : position+requestEnd]
	position += requestEnd + 1
	target, ok := parseHTTPRequestLine(requestLine)
	if !ok {
		return "", false
	}
	if !consumeAccessLogWhitespace(logLine, &position) {
		return "", false
	}
	status, ok := consumeAccessLogToken(logLine, &position)
	if !ok || len(status) != 3 || !allASCIIDigits(status) {
		return "", false
	}
	size, ok := consumeAccessLogToken(logLine, &position)
	if !ok || size != "-" && !allASCIIDigits(size) {
		return "", false
	}
	return target, true
}

// extractPrefixedRequestTarget preserves the compact access-record form used
// by direct collectors and existing integrations: host METHOD target HTTP/x.
func extractPrefixedRequestTarget(logLine string) (string, bool) {
	fields := strings.Fields(logLine)
	if len(fields) < 4 || !isAccessLogSource(fields[0]) {
		return "", false
	}
	return parseHTTPRequestLine(strings.Join(fields[1:4], " "))
}

func isAccessLogSource(value string) bool {
	if _, ok := canonicalSourceAddr(value); ok {
		return true
	}
	addressPort, err := netip.ParseAddrPort(value)
	if err != nil {
		return false
	}
	_, ok := canonicalSourceAddr(addressPort.Addr().String())
	return ok && addressPort.Port() != 0
}

func consumeAccessLogToken(input string, position *int) (string, bool) {
	consumeAccessLogWhitespace(input, position)
	if *position >= len(input) {
		return "", false
	}
	start := *position
	for *position < len(input) {
		switch input[*position] {
		case ' ', '\t', '\r', '\n':
			return input[start:*position], *position > start
		default:
			(*position)++
		}
	}
	return input[start:*position], *position > start
}

func consumeAccessLogWhitespace(input string, position *int) bool {
	start := *position
	for *position < len(input) && (input[*position] == ' ' || input[*position] == '\t') {
		(*position)++
	}
	return *position > start
}

func parseHTTPRequestLine(requestLine string) (string, bool) {
	if len(requestLine) == 0 || len(requestLine) > maxRequestTargetBytes+64 || strings.ContainsAny(requestLine, "\t\r\n") {
		return "", false
	}
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 || !validHTTPMethod(parts[0]) || !validHTTPVersion(parts[2]) || !validRequestTarget(parts[1]) {
		return "", false
	}
	return parts[1], true
}

func validHTTPMethod(method string) bool {
	if len(method) == 0 || len(method) > 32 {
		return false
	}
	for index := 0; index < len(method); index++ {
		character := method[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

func validHTTPVersion(version string) bool {
	if !strings.HasPrefix(version, "HTTP/") {
		return false
	}
	number := strings.TrimPrefix(version, "HTTP/")
	if number == "" {
		return false
	}
	dotSeen := false
	for index := 0; index < len(number); index++ {
		if number[index] == '.' && !dotSeen && index > 0 && index+1 < len(number) {
			dotSeen = true
			continue
		}
		if number[index] < '0' || number[index] > '9' {
			return false
		}
	}
	return true
}

func validRequestTarget(target string) bool {
	if len(target) == 0 || len(target) > maxRequestTargetBytes {
		return false
	}
	for index := 0; index < len(target); index++ {
		if target[index] <= ' ' || target[index] == 0x7f {
			return false
		}
	}
	return true
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func extractTopLevelJSONRequestTarget(logLine string) (string, bool) {
	decoder := json.NewDecoder(strings.NewReader(logLine))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", false
	}

	seen := make(map[string]struct{})
	candidate := ""
	hasCandidate := false
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return "", false
		}
		key, ok := keyToken.(string)
		if !ok {
			return "", false
		}
		if _, duplicate := seen[key]; duplicate {
			return "", false
		}
		seen[key] = struct{}{}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", false
		}
		_, directTarget := jsonRequestTargetFieldNames[key]
		_, requestLine := jsonRequestLineFieldNames[key]
		if !directTarget && !requestLine {
			continue
		}
		var encoded string
		if err := json.Unmarshal(value, &encoded); err != nil {
			return "", false
		}
		target := encoded
		if requestLine {
			var valid bool
			target, valid = parseHTTPRequestLine(encoded)
			if !valid {
				return "", false
			}
		} else if !validRequestTarget(target) {
			return "", false
		}
		if hasCandidate && candidate != target {
			return "", false
		}
		candidate = target
		hasCandidate = true
	}

	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return "", false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", false
	}
	return candidate, hasCandidate
}

// EvaluateThreshold returns true if the IP has reached the limit and should be banned
func (e *Engine) EvaluateThreshold(ip string, ruleID string, customThreshold, customWindow int) bool {
	threshold := customThreshold
	window := customWindow

	if threshold <= 0 {
		threshold = e.defaultThreshold
	}
	if window <= 0 {
		window = e.defaultWindow
	}
	if threshold <= 1 {
		return true // Instant ban if threshold is 1 or less
	}

	key := ip + ":" + ruleID
	now := time.Now().Unix()
	e.trackerMu.Lock()
	defer e.trackerMu.Unlock()

	var timestamps []int64
	if val, ok := e.tracker.Load(key); ok {
		timestamps = val.([]int64)
	}

	// Filter valid timestamps within window
	var valid []int64
	windowStart := now - int64(window)
	for _, t := range timestamps {
		if t >= windowStart {
			valid = append(valid, t)
		}
	}

	valid = append(valid, now)

	if len(valid) >= threshold {
		e.tracker.Delete(key)
		return true
	}

	e.tracker.Store(key, valid)
	return false
}

func (e *Engine) GarbageCollector() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		e.trackerMu.Lock()
		e.tracker.Range(func(key, value interface{}) bool {
			timestamps := value.([]int64)
			var valid []int64
			// Get window safely from default, exact GC for specific custom windows is complex so we do a general cleanup
			// Using 1 hour as max TTL for cleanup to ensure memory safety
			windowStart := now - 3600
			for _, t := range timestamps {
				if t >= windowStart {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				e.tracker.Delete(key)
			} else {
				e.tracker.Store(key, valid)
			}
			return true
		})
		e.trackerMu.Unlock()
	}
}

var jsonIPFieldNames = map[string]struct{}{
	"ClientHost": {},
	"remote_ip":  {},
	"remoteAddr": {},
	"client_ip":  {},
	"ClientAddr": {},
}

func ExtractIP(logLine string) string {
	logLine = strings.TrimSpace(logLine)
	if logLine == "" {
		return ""
	}

	// A leading address is authoritative for conventional access logs. Checking it
	// first prevents attacker-controlled text later in the record from replacing it.
	leadingEnd := strings.IndexAny(logLine, " \t\r\n")
	if leadingEnd < 0 {
		leadingEnd = len(logLine)
	}
	if addr, ok := canonicalSourceAddr(logLine[:leadingEnd]); ok {
		return addr.String()
	}

	// Structured logs are accepted only when the complete record is one JSON
	// object and an unambiguous supported field exists at its top level.
	if addr, ok := extractTopLevelJSONAddr(logLine); ok {
		return addr.String()
	}

	return ""
}

func extractTopLevelJSONAddr(logLine string) (netip.Addr, bool) {
	decoder := json.NewDecoder(strings.NewReader(logLine))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return netip.Addr{}, false
	}

	seen := make(map[string]struct{})
	var candidate netip.Addr
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return netip.Addr{}, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return netip.Addr{}, false
		}
		if _, duplicate := seen[key]; duplicate {
			return netip.Addr{}, false
		}
		seen[key] = struct{}{}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return netip.Addr{}, false
		}
		if _, supported := jsonIPFieldNames[key]; !supported {
			continue
		}

		var encodedAddr string
		if err := json.Unmarshal(value, &encodedAddr); err != nil {
			return netip.Addr{}, false
		}
		addr, valid := canonicalSourceAddr(encodedAddr)
		if !valid {
			return netip.Addr{}, false
		}
		if candidate.IsValid() && candidate != addr {
			return netip.Addr{}, false
		}
		candidate = addr
	}

	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return netip.Addr{}, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return netip.Addr{}, false
	}
	return candidate, candidate.IsValid()
}

func canonicalSourceAddr(raw string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() {
		return netip.Addr{}, false
	}
	return addr, true
}
