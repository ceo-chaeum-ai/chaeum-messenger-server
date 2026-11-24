// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

// Package searchproto is what the messenger server shares with its search worker: the messages they
// exchange over the socket, and the rule for cutting text into searchable pieces. The server uses the
// same rule to scan posts older than the worker's index, so both give the same answer. The worker is a
// separate program and is not part of this repository.
package searchproto

import (
	"strings"
	"unicode"
)

// Doc is one post as the server hands it over for indexing.
type Doc struct {
	ID       string `json:"id"`
	Channel  string `json:"channel"`
	User     string `json:"user"`
	CreateAt int64  `json:"create_at"`
	Text     string `json:"text"`
	Ext      string `json:"ext,omitempty"` // files only: extension without the dot, lower case
}

// Query is one search. Channels is the list the server computed the user may read; the worker does
// not judge permissions.
type Query struct {
	Terms         []string `json:"terms"`
	Or            bool     `json:"or,omitempty"`
	Excluded      []string `json:"excluded,omitempty"`
	Channels      []string `json:"channels"`
	FromUsers     []string `json:"from_users,omitempty"`
	ExcludedUsers []string `json:"excluded_users,omitempty"`
	After         int64    `json:"after,omitempty"`  // CreateAt >= After
	Before        int64    `json:"before,omitempty"` // CreateAt < Before
	Limit         int      `json:"limit"`
	Exts          []string `json:"exts,omitempty"` // files only
	ExcludedExts  []string `json:"excluded_exts,omitempty"`
}

// Hit is a matching post.
type Hit struct {
	ID       string `json:"id"`
	CreateAt int64  `json:"create_at"`
}

type tok struct {
	k uint64
	p uint32
}

func key(a, b rune) uint64 { return uint64(a)<<32 | uint64(b) }

func isSep(r rune) bool {
	switch r {
	case '#', '@', '_', '-', '+', '&', '%', '$':
		return false
	}
	return unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsSymbol(r)
}

// Tokens cuts text into overlapping two-character pieces inside each word, with character positions.
// A one-character word becomes (char, 0). Korean has no usable word boundary inside an eojeol, so
// "회의록을" must be findable by "회의록"; positions keep the two-character pieces honest.
func Tokens(s string, out []tok) []tok {
	out = out[:0]
	var prev rune
	var have bool
	var wl int
	var p uint32
	flush := func() {
		if wl == 1 {
			out = append(out, tok{key(prev, 0), p - 1})
		}
	}
	for _, r := range strings.ToLower(s) {
		if isSep(r) {
			flush()
			have, wl = false, 0
			p++
			continue
		}
		if have {
			out = append(out, tok{key(prev, r), p - 1})
		}
		prev, have = r, true
		wl++
		p++
	}
	flush()
	return out
}

// termTokens prepares a search term. A one-character term cannot use (char, 0), which only matches
// one-character words; ok is false and the caller treats the term as unsearchable.
func termTokens(term string) ([]tok, bool) {
	t := Tokens(strings.TrimRight(term, "*"), nil)
	return t, len(t) > 0
}

// Matcher decides whether a text satisfies the terms of a query, with the same rules the index uses.
// The server uses it to scan posts older than the index.
type Matcher struct {
	or       bool
	terms    []compiled
	excluded []compiled
}

type compiled struct {
	toks   []tok
	pieces []string // lower-case words of the term: a cheap necessary condition before tokenizing the text
}

func compile(terms []string) []compiled {
	out := make([]compiled, 0, len(terms))
	for _, t := range terms {
		c := compiled{}
		c.toks, _ = termTokens(t)
		c.pieces = strings.FieldsFunc(strings.ToLower(strings.TrimRight(t, "*")), isSep)
		out = append(out, c)
	}
	return out
}

func Compile(q *Query) *Matcher {
	return &Matcher{or: q.Or, terms: compile(q.Terms), excluded: compile(q.Excluded)}
}

func MatchText(q *Query, text string) bool { return Compile(q).Match(text) }

func (m *Matcher) Match(text string) bool {
	lower := strings.ToLower(text)
	var set map[tok]struct{}
	var toks []tok
	has := func(c compiled) bool {
		if len(c.toks) == 0 {
			return false
		}
		for _, piece := range c.pieces {
			if !strings.Contains(lower, piece) {
				return false
			}
		}
		if set == nil {
			toks = Tokens(lower, nil)
			set = make(map[tok]struct{}, len(toks))
			for _, t := range toks {
				set[t] = struct{}{}
			}
		}
		for _, t := range toks {
			if t.k != c.toks[0].k {
				continue
			}
			all := true
			for _, x := range c.toks[1:] {
				if _, found := set[tok{x.k, t.p + x.p - c.toks[0].p}]; !found {
					all = false
					break
				}
			}
			if all {
				return true
			}
		}
		return false
	}
	for _, c := range m.excluded {
		if has(c) {
			return false
		}
	}
	if len(m.terms) == 0 {
		return true
	}
	for _, c := range m.terms {
		if has(c) {
			if m.or {
				return true
			}
		} else if !m.or {
			return false
		}
	}
	return !m.or
}
