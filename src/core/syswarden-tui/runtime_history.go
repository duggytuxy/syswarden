package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Runtime history has no physical-hit column. Administrative enforcement
// remains visible without entering the attack metrics or active registry.
func runtimeLifecycleHistoryLines(raw json.RawMessage) ([]string, error) {
	envelope, err := decodeTUIGRCKPIEvidence(raw)
	if err != nil {
		return nil, err
	}
	snapshot := envelope.Lifecycle.RuntimeLocalSnapshot
	if snapshot == nil {
		return []string{"Local native lifecycle history is not reported by this snapshot."}, nil
	}
	lines := []string{fmt.Sprintf("Captured: %s | Active: %d | Deleted: %d | Expired: %d | Tombstoned: %d",
		snapshot.CapturedAt, snapshot.Active, snapshot.Deleted, snapshot.Expired, snapshot.Tombstoned)}
	if snapshot.Truncated {
		lines = append(lines, "History is truncated; complete evidence is unavailable.")
	}
	for _, claim := range snapshot.Claims {
		line := fmt.Sprintf("%s | state=%s | cause=%s | generation=%d | transition=%s",
			claim.Entry, claim.State, claim.Cause, claim.Generation, claim.TransitionAt)
		if claim.ExpiresAt != "" {
			line += " | expires=" + claim.ExpiresAt
		}
		if claim.ConfirmedAt != "" {
			line += " | absence-confirmed=" + claim.ConfirmedAt
		}
		lines = append(lines, line)
	}
	if len(snapshot.Claims) == 0 {
		lines = append(lines, "No retained runtime claims.")
	}
	return lines, nil
}

var runtimeHistoryOpen bool

func showRuntimeLifecycleHistory(mainFlex *tview.Flex) {
	mu.Lock()
	raw := append(json.RawMessage(nil), data.WAF.GRCKPI...)
	status := dashboardOperationalStatus(data, fetchError, dashboardClock, false)
	mu.Unlock()
	lines, err := runtimeLifecycleHistoryLines(raw)
	if err != nil {
		lines = []string{"Runtime lifecycle history is unavailable: " + err.Error()}
	}
	text := tview.NewTextView().SetDynamicColors(false).SetWrap(false).SetScrollable(true)
	text.SetBorder(true).SetTitle(" Runtime Lifecycle History ")
	text.SetText(status + "\n\n" + strings.Join(lines, "\n"))
	closeHistory := func() {
		runtimeHistoryOpen = false
		app.SetRoot(mainFlex, true).SetFocus(bannedTable)
	}
	button := tview.NewButton("Close").SetSelectedFunc(closeHistory)
	text.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			closeHistory()
		}
	})
	panel := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(text, 0, 1, true).AddItem(button, 1, 0, false)
	runtimeHistoryOpen = true
	app.SetRoot(panel, true).SetFocus(text)
}
