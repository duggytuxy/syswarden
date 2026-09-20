package engine

import (
	"regexp/syntax"
	"strings"
)

type regexPrefilter struct {
	literal      string
	foldCase     bool
	foldPrefix   []int
	alternatives []*regexPrefilter
}

type regexScanText struct {
	text    string
	checked bool
	ascii   bool
}

// Non-ASCII and invalid UTF-8 inputs always use the complete expression.
// This keeps Unicode simple-fold equivalences under Go regexp's authority.
func (content *regexScanText) matches(filter *regexPrefilter) bool {
	if filter == nil {
		return true
	}
	if !content.checked {
		content.ascii, content.checked = true, true
		for i := 0; i < len(content.text); i++ {
			if content.text[i] >= 128 {
				content.ascii = false
				break
			}
		}
	}
	if !content.ascii {
		return true
	}
	if len(filter.alternatives) > 0 {
		for _, branch := range filter.alternatives {
			if content.matches(branch) {
				return true
			}
		}
		return false
	}
	if filter.foldCase {
		return filter.containsASCIIFold(content.text)
	}
	return strings.Contains(content.text, filter.literal)
}

// KMP keeps repeated attacker-controlled prefixes linear in the input length.
// The prefix table is immutable and allocated only when the catalog is loaded.
func (filter *regexPrefilter) containsASCIIFold(text string) bool {
	if len(filter.literal) == 0 {
		return true
	}
	matched := 0
	for i := 0; i < len(text); i++ {
		current := text[i]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		for matched > 0 && current != filter.literal[matched] {
			matched = filter.foldPrefix[matched-1]
		}
		if current == filter.literal[matched] {
			matched++
			if matched == len(filter.literal) {
				return true
			}
		}
	}
	return false
}

func foldLiteralPrefix(literal string) []int {
	prefix := make([]int, len(literal))
	matched := 0
	for i := 1; i < len(literal); i++ {
		for matched > 0 && literal[i] != literal[matched] {
			matched = prefix[matched-1]
		}
		if literal[i] == literal[matched] {
			matched++
		}
		prefix[i] = matched
	}
	return prefix
}

// Bind only to the actual compiled expression after flags and HOST expansion.
// The result is a necessary condition, never a substitute for full matching.
func compileRegexPrefilter(pattern string) *regexPrefilter {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	condition, score := requiredRegexLiteral(tree)
	if score < 3 {
		return nil
	}
	return condition
}

func requiredRegexLiteral(tree *syntax.Regexp) (*regexPrefilter, int) {
	if tree == nil {
		return nil, 0
	}
	switch tree.Op {
	case syntax.OpLiteral:
		if len(tree.Rune) == 0 {
			return nil, 0
		}
		for _, r := range tree.Rune {
			if r >= 128 {
				return nil, 0
			}
		}
		literal := string(tree.Rune)
		fold := tree.Flags&syntax.FoldCase != 0
		if fold {
			literal = strings.ToLower(literal)
		}
		condition := &regexPrefilter{literal: literal, foldCase: fold}
		if fold {
			condition.foldPrefix = foldLiteralPrefix(literal)
		}
		return condition, len(tree.Rune)
	case syntax.OpCapture, syntax.OpPlus:
		return requiredRegexLiteral(tree.Sub[0])
	case syntax.OpRepeat:
		if tree.Min > 0 {
			return requiredRegexLiteral(tree.Sub[0])
		}
	case syntax.OpConcat:
		var chosen *regexPrefilter
		length := 0
		for _, part := range tree.Sub {
			candidate, score := requiredRegexLiteral(part)
			if score > length {
				chosen, length = candidate, score
			}
		}
		return chosen, length
	case syntax.OpAlternate:
		if len(tree.Sub) == 0 || len(tree.Sub) > 32 {
			return nil, 0
		}
		alternatives := make([]*regexPrefilter, 0, len(tree.Sub))
		minimum := int(^uint(0) >> 1)
		for _, branch := range tree.Sub {
			condition, score := requiredRegexLiteral(branch)
			if condition == nil {
				return nil, 0
			}
			alternatives = append(alternatives, condition)
			if score < minimum {
				minimum = score
			}
		}
		return &regexPrefilter{alternatives: alternatives}, minimum
	}
	return nil, 0
}
