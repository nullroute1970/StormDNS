// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package domainmatcher

import (
	"sort"
	"strings"

	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
)

type Action uint8

const (
	ActionFormatError Action = iota
	ActionNoData
	ActionProcess
)

type Decision struct {
	Action       Action
	Reason       string
	Question     DnsParser.Question
	RequestName  string
	BaseDomain   string
	Labels       string
	QuestionType uint16
}

type Matcher struct {
	allowedDomains []string
	root           *domainNode
	minLabelLength int
}

type domainNode struct {
	children map[string]*domainNode
	domain   string
}

func New(domains []string, minLabelLength int) *Matcher {
	normalized := normalizeDomains(domains)
	if minLabelLength < 1 {
		minLabelLength = 3
	}

	return &Matcher{
		allowedDomains: normalized,
		root:           buildDomainTrie(normalized),
		minLabelLength: minLabelLength,
	}
}

func (m *Matcher) Domains() []string {
	if len(m.allowedDomains) == 0 {
		return nil
	}

	domains := make([]string, len(m.allowedDomains))
	copy(domains, m.allowedDomains)
	return domains
}

func (m *Matcher) Match(parsed DnsParser.LitePacket) Decision {
	if !parsed.HasQuestion {
		return Decision{Action: ActionFormatError, Reason: "missing-question"}
	}

	q0 := parsed.FirstQuestion
	requestName := normalizeParsedDomain(q0.Name)
	if requestName == "" || requestName == "." {
		return Decision{Action: ActionFormatError, Reason: "empty-qname"}
	}

	baseDomain, labels, matched := findAllowedDomain(requestName, m.root)
	if !matched {
		return Decision{
			Action:       ActionNoData,
			Reason:       "unauthorized-domain",
			Question:     q0,
			RequestName:  requestName,
			QuestionType: q0.Type,
		}
	}

	if q0.Type != Enums.DNS_RECORD_TYPE_TXT {
		return Decision{
			Action:       ActionNoData,
			Reason:       "unsupported-qtype",
			Question:     q0,
			RequestName:  requestName,
			BaseDomain:   baseDomain,
			QuestionType: q0.Type,
		}
	}

	if labels == "" {
		return Decision{
			Action:       ActionNoData,
			Reason:       "missing-vpn-labels",
			Question:     q0,
			RequestName:  requestName,
			BaseDomain:   baseDomain,
			QuestionType: q0.Type,
		}
	}

	if len(labels) < m.minLabelLength {
		return Decision{
			Action:       ActionNoData,
			Reason:       "labels-too-short",
			Question:     q0,
			RequestName:  requestName,
			BaseDomain:   baseDomain,
			Labels:       labels,
			QuestionType: q0.Type,
		}
	}

	return Decision{
		Action:       ActionProcess,
		Reason:       "matched-vpn-domain",
		Question:     q0,
		RequestName:  requestName,
		BaseDomain:   baseDomain,
		Labels:       labels,
		QuestionType: q0.Type,
	}
}

func normalizeDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}

	unique := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		normalized := normalizeDomain(domain)
		if normalized == "" || normalized == "." {
			continue
		}
		unique[normalized] = struct{}{}
	}

	if len(unique) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(unique))
	for domain := range unique {
		normalized = append(normalized, domain)
	}

	sort.Slice(normalized, func(i, j int) bool {
		if len(normalized[i]) == len(normalized[j]) {
			return normalized[i] < normalized[j]
		}
		return len(normalized[i]) > len(normalized[j])
	})

	return normalized
}

func buildDomainTrie(domains []string) *domainNode {
	if len(domains) == 0 {
		return nil
	}

	root := &domainNode{}
	for _, domain := range domains {
		node := root
		offset := len(domain)
		for offset > 0 {
			start := strings.LastIndexByte(domain[:offset], '.')
			labelStart := start + 1
			label := domain[labelStart:offset]
			if node.children == nil {
				node.children = make(map[string]*domainNode, 2)
			}
			child := node.children[label]
			if child == nil {
				child = &domainNode{}
				node.children[label] = child
			}
			node = child
			if start < 0 {
				break
			}
			offset = start
		}
		node.domain = domain
	}
	return root
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func normalizeParsedDomain(domain string) string {
	if len(domain) != 0 && domain[len(domain)-1] == '.' {
		return domain[:len(domain)-1]
	}
	return domain
}

func findAllowedDomain(requestName string, root *domainNode) (baseDomain string, labels string, matched bool) {
	if root == nil || requestName == "" {
		return "", "", false
	}

	node := root
	offset := len(requestName)
	matchedPos := -1

	for offset > 0 {
		start := strings.LastIndexByte(requestName[:offset], '.')
		labelStart := start + 1
		child := node.children[requestName[labelStart:offset]]
		if child == nil {
			break
		}
		node = child
		if node.domain != "" {
			baseDomain = node.domain
			matchedPos = labelStart
		}
		if start < 0 {
			break
		}
		offset = start
	}

	if matchedPos < 0 {
		return "", "", false
	}
	if matchedPos == 0 {
		return baseDomain, "", true
	}

	labels = requestName[:matchedPos-1]
	if strings.IndexByte(labels, '.') >= 0 {
		labels = stripLabelDots(labels)
	}
	return baseDomain, labels, true
}

func stripLabelDots(labels string) string {
	if strings.IndexByte(labels, '.') == -1 {
		return labels
	}

	var b strings.Builder
	b.Grow(len(labels))
	for i := 0; i < len(labels); i++ {
		if labels[i] != '.' {
			b.WriteByte(labels[i])
		}
	}
	return b.String()
}
