package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Stream kernel and WAAP alert events",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := alertSignalContext(cmd.Context())
		defer stop()
		if !term.IsTerminal(int(os.Stdout.Fd())) {
			runTextModeFallback(ctx)
			return nil
		}
		return runAlertsTUI(ctx)
	},
}

const alertUIQueueCapacity = 128

type alertUIUpdate struct {
	redraw bool
	apply  func()
}

type alertUIQueue struct {
	ctx     context.Context
	app     *tview.Application
	updates chan alertUIUpdate
	done    chan struct{}
}

func newAlertUIQueue(ctx context.Context, app *tview.Application) *alertUIQueue {
	return &alertUIQueue{
		ctx:     ctx,
		app:     app,
		updates: make(chan alertUIUpdate, alertUIQueueCapacity),
		done:    make(chan struct{}),
	}
}

func (queue *alertUIQueue) run() {
	defer close(queue.done)
	for {
		select {
		case <-queue.ctx.Done():
			return
		case update := <-queue.updates:
			if queue.ctx.Err() != nil {
				return
			}
			if update.redraw {
				queue.app.QueueUpdateDraw(update.apply)
			} else {
				queue.app.QueueUpdate(update.apply)
			}
		}
	}
}

func (queue *alertUIQueue) enqueue(redraw bool, update func()) bool {
	if queue.ctx.Err() != nil {
		return false
	}
	select {
	case <-queue.ctx.Done():
		return false
	case queue.updates <- alertUIUpdate{redraw: redraw, apply: update}:
		return true
	}
}

func alertSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

type alertTUISource func(context.Context, *alertUIQueue, *tview.Table, *tview.TextView)

func runAlertsTUI(parent context.Context) error {
	return runAlertsTUIWithSources(parent, tview.NewApplication(), StreamKernelLogs, streamWAF)
}

func runAlertsTUIWithSources(parent context.Context, app *tview.Application, kernelSource, wafSource alertTUISource) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	table := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0) // Keep header fixed

		// Add header row.
	headers := []string{"TIMESTAMP", "MODULE", "ACTION", "SOURCE IP", "TARGET (PORT/JAIL/SERVICES)"}
	for col, header := range headers {
		table.SetCell(0, col, tview.NewTableCell(header).
			SetTextColor(tcell.ColorGray).
			SetSelectable(false).
			SetAlign(tview.AlignCenter).
			SetExpansion(1)) // Ensure even expansion
	}

	kernelStatus := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).
		SetTextColor(tcell.ColorYellow).
		SetText(formatAlertSourceStatus("KERNEL", alertSourceStatus{}))
	wafStatus := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).
		SetTextColor(tcell.ColorYellow).
		SetText(formatAlertSourceStatus("WAF", alertSourceStatus{}))
	content := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(kernelStatus, 1, 0, false).
		AddItem(wafStatus, 1, 0, false).
		AddItem(table, 0, 1, true)

		// Frame wrapping the source status and table.
	frame := tview.NewFrame(content).
		SetBorders(0, 0, 0, 0, 0, 0).
		AddText(" [ SYSWARDEN CLI DASHBOARD (Live Alerts) ] ", true, tview.AlignCenter, tcell.ColorGreen).
		AddText(" Live-only sources start at the current boundary. Press Ctrl+C to stop. ", false, tview.AlignCenter, tcell.ColorYellow)

	frame.SetBorder(true).
		SetBorderColor(tcell.ColorBlue).
		SetTitleColor(tcell.ColorWhite).
		SetTitleAlign(tview.AlignCenter)

	uiQueue := newAlertUIQueue(ctx, app)
	var streams sync.WaitGroup
	var startStreams sync.Once
	uiStarted := false
	start := func() {
		startStreams.Do(func() {
			uiStarted = true
			go uiQueue.run()
			streams.Add(2)
			go func() {
				defer streams.Done()
				kernelSource(ctx, uiQueue, table, kernelStatus)
			}()
			go func() {
				defer streams.Done()
				wafSource(ctx, uiQueue, table, wafStatus)
			}()
		})
	}

	applicationReady := make(chan struct{})
	applicationReturned := make(chan struct{})
	var markApplicationReady sync.Once
	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		// Prevent a late first draw from adding workers concurrently with Wait.
		startStreams.Do(func() {})
		streams.Wait()
		if uiStarted {
			select {
			case <-uiQueue.done:
			case <-applicationReturned:
				// An EventError can end tview while an update is queued. Stream
				// reaping must not depend on that UI worker returning.
			}
		}
		select {
		case <-applicationReady:
			app.Stop()
		case <-applicationReturned:
			// Run failed before the first draw, so there is no screen to stop.
		}
		close(shutdownDone)
	}()

	app.SetAfterDrawFunc(func(tcell.Screen) {
		markApplicationReady.Do(func() { close(applicationReady) })
		start()
	})
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			// Keep the tview event loop alive until the context-bound followers
			// have exited and been reaped. This lets any already queued update
			// complete instead of stranding QueueUpdate callers after Run.
			cancel()
			return nil
		}
		return event
	})

	err := app.SetRoot(frame, true).EnableMouse(true).Run()
	close(applicationReturned)
	cancel()
	<-shutdownDone
	return err
}

func addRow(queue *alertUIQueue, table *tview.Table, redraw bool, date, module, action, src, targetInfo string, modColor, actColor tcell.Color) bool {
	update := func() {
		row := table.GetRowCount()
		table.SetCell(row, 0, tview.NewTableCell(date).SetTextColor(tcell.ColorGray).SetAlign(tview.AlignCenter))
		table.SetCell(row, 1, tview.NewTableCell(module).SetTextColor(modColor).SetAlign(tview.AlignCenter))
		table.SetCell(row, 2, tview.NewTableCell(action).SetTextColor(actColor).SetAlign(tview.AlignCenter))
		table.SetCell(row, 3, tview.NewTableCell(src).SetTextColor(tcell.ColorYellow).SetAlign(tview.AlignCenter))
		table.SetCell(row, 4, tview.NewTableCell(targetInfo).SetTextColor(tcell.ColorGray).SetAlign(tview.AlignCenter))

		// Auto scroll to the end
		table.ScrollToEnd()
	}
	return queue.enqueue(redraw, update)
}

func StreamKernelLogs(ctx context.Context, queue *alertUIQueue, table *tview.Table, statusView *tview.TextView) {
	runKernelSource(
		ctx,
		func(phase alertStreamPhase, line string) bool {
			row, ok := parseKernelAlertRow(line, phase, time.Now())
			if !ok {
				return false
			}
			return addRow(queue, table, false, row.Date, row.Module, string(row.Phase)+" "+row.Action, row.Source, row.Target, row.ModuleColor, row.ActionColor)
		},
		func(status alertSourceStatus) {
			queue.enqueue(true, func() {
				statusView.SetText(formatAlertSourceStatus("KERNEL", status))
			})
		},
	)
}

func streamWAF(ctx context.Context, queue *alertUIQueue, table *tview.Table, statusView *tview.TextView) {
	runWAFSource(
		ctx,
		func(phase alertStreamPhase, line string) bool {
			row, err := parseWAFAlertRow(line, phase, time.Now())
			if err != nil {
				addRow(queue, table, true, time.Now().Format("2006-01-02 15:04:05"), "SYSWARDEN ERR", string(phase)+" JSON ERROR", err.Error(), boundedSingleLine(line), tcell.ColorRed, tcell.ColorRed)
				return false
			}
			return addRow(queue, table, false, row.Date, row.Module, string(row.Phase)+" "+row.Action, row.Source, row.Target, row.ModuleColor, row.ActionColor)
		},
		func(status alertSourceStatus) {
			queue.enqueue(true, func() {
				statusView.SetText(formatAlertSourceStatus("WAF", status))
			})
		},
	)
}

func init() {
	rootCmd.AddCommand(alertsCmd)
}

func runTextModeFallback(ctx context.Context) {
	fmt.Println("=== SYSWARDEN TEXT MODE FALLBACK (Non-Interactive) ===")
	fmt.Println("Streaming new LIVE telemetry from the current boundary to standard output...")

	var streams sync.WaitGroup
	streams.Add(2)
	go func() {
		defer streams.Done()
		StreamKernelLogsText(ctx)
	}()
	go func() {
		defer streams.Done()
		streamWAFText(ctx)
	}()

	<-ctx.Done()
	streams.Wait()
}

func StreamKernelLogsText(ctx context.Context) {
	reportStatus := newAlertTextStatusReporter(os.Stdout, "KERNEL")
	runKernelSource(
		ctx,
		func(phase alertStreamPhase, line string) bool {
			row, ok := parseKernelAlertRow(line, phase, time.Now())
			if ok {
				fmt.Println(formatAlertTextRow(row))
			}
			return ok
		},
		reportStatus,
	)
}

func streamWAFText(ctx context.Context) {
	reportStatus := newAlertTextStatusReporter(os.Stdout, "WAF")
	runWAFSource(
		ctx,
		func(phase alertStreamPhase, line string) bool {
			row, err := parseWAFAlertRow(line, phase, time.Now())
			if err != nil {
				fmt.Printf("[%s] [%s] [SYSWARDEN ERR] [JSON ERROR] %s -> %s\n", time.Now().Format("2006-01-02 15:04:05"), phase, err.Error(), boundedSingleLine(line))
				return false
			}
			fmt.Println(formatAlertTextRow(row))
			return true
		},
		reportStatus,
	)
}
