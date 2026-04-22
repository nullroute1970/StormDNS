// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"stormdns-go/internal/client"
	"stormdns-go/internal/config"
	"stormdns-go/internal/runtimepath"
	"stormdns-go/internal/version"
)

func waitForExitInput() {
	_, _ = fmt.Fprint(os.Stderr, "Press Enter to exit...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

// promptStartupMode shows an interactive prompt when STARTUP_MODE is "ask".
// Returns true if the user chooses to start from log files.
// Auto-selects client_resolvers.txt after 10 seconds with no input.
func promptStartupMode(preConfig config.ClientStartupPreConfig) bool {
	switch preConfig.StartupMode {
	case "resolvers":
		return false
	case "logs":
		return true
	}

	// Interactive mode: ask the user with a 10-second timeout.
	_, _ = fmt.Fprintln(os.Stderr)
	_, _ = fmt.Fprintln(os.Stderr, "How do you want to start?")
	_, _ = fmt.Fprintln(os.Stderr, "  [1] Start from client_resolvers.txt (full scan)")
	_, _ = fmt.Fprintln(os.Stderr, "  [2] Start from log files (fast start)")
	_, _ = fmt.Fprint(os.Stderr, "Enter your choice (auto-selects 1 in 10 seconds): ")

	inputCh := make(chan byte, 1)
	go func() {
		buf := make([]byte, 1)
		if _, err := os.Stdin.Read(buf); err == nil {
			inputCh <- buf[0]
		} else {
			inputCh <- '1'
		}
	}()

	select {
	case b := <-inputCh:
		_, _ = fmt.Fprintln(os.Stderr)
		return b == '2'
	case <-time.After(10 * time.Second):
		_, _ = fmt.Fprint(os.Stderr, "\nAuto-selected: client_resolvers.txt\n")
		return false
	}
}

func main() {
	configPath := flag.String("config", "client_config.toml", "Path to client configuration file")
	resolversPath := flag.String("resolvers", "", "Path to resolver file override (optional)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	configFlags, err := config.NewClientConfigFlagBinder(flag.CommandLine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Client flag setup failed: %v\n", err)
		os.Exit(2)
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("StormDNS Client Version: %s\n", version.GetVersion())
		return
	}

	resolvedConfigPath := runtimepath.Resolve(*configPath)
	overrides := configFlags.Overrides()
	if *resolversPath != "" {
		resolvedResolversPath := runtimepath.Resolve(*resolversPath)
		overrides.ResolversFilePath = &resolvedResolversPath
	}

	// Peek at startup-mode fields before loading the full config so we can
	// present the prompt without side-effects.
	preConfig := config.PeekClientStartupConfig(resolvedConfigPath)
	fromLogs := promptStartupMode(preConfig)

	var app *client.Client
	if fromLogs {
		entries := client.ScanResolverCacheLogs(
			preConfig.ResolvedLogDir(),
			preConfig.LogScanMaxDays,
			preConfig.LogScanMaxResolvers,
		)
		if len(entries) > 0 {
			app, err = client.BootstrapFromLogs(resolvedConfigPath, entries, overrides)
		} else {
			// No usable log entries found — silently fall back to the normal path.
			app, err = client.Bootstrap(resolvedConfigPath, overrides)
		}
	} else {
		app, err = client.Bootstrap(resolvedConfigPath, overrides)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Client startup failed: %v\n", err)
		waitForExitInput()
		os.Exit(1)
	}

	app.PrintBanner()

	log := app.Log()
	if log != nil {
		log.Infof("\U0001F680 <green>StormDNS Client Started</green>")
		log.Infof("\U0001F4C4 <green>Configuration loaded from: <cyan>%s</cyan></green>", resolvedConfigPath)
		log.Infof("\U0001F5C2  <green>Connection Catalog: <cyan>%d</cyan> domain-resolver pairs</green>", len(app.Connections()))
	}

	// Wait for termination signal
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(sigCtx); err != nil {
		if log != nil {
			log.Errorf("Runtime error: %v", err)
		}
	}

	if log != nil {
		log.Infof("\U0001F6D1 <red>Shutting down...</red>")
	}
}
