// Copyright (c) 2026-present ChaeumAI. Licensed under the same terms as the rest of this repository (see LICENSE.txt).

package searchproto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchText(t *testing.T) {
	m := func(text string, q Query) bool { return MatchText(&q, text) }
	require.True(t, m("주간 회의록을 올립니다 #회의", Query{Terms: []string{"회의록"}}))
	require.False(t, m("회의 끝나고 록 음악", Query{Terms: []string{"회의록"}}))
	require.True(t, m("Budget report for Q3, final", Query{Terms: []string{"budget", "REPORT"}}))
	require.True(t, m("Budget report for Q3, final", Query{Terms: []string{"report for"}}))
	require.False(t, m("Budget report for Q3, final", Query{Terms: []string{"report final"}}))
	require.True(t, m("예산 보고서 초안", Query{Terms: []string{"budget", "예산"}, Or: true}))
	require.False(t, m("주간 회의록을 올립니다", Query{Terms: []string{"회의"}, Excluded: []string{"회의록"}}))
	require.True(t, m("Budget report", Query{Terms: []string{"repo*"}}))
}
