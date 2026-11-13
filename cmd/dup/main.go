// Command dup is the proxy-duplicator: a duplication + failover tunnel
// multiplexer running over N parallel SSH (or plain TCP) tunnels.
//
// Usage:
//
//	dup server -c server.yaml
//	dup client -c client.yaml
//	dup version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"proxy-duplicator/internal/client"
	"proxy-duplicator/internal/config"
	"proxy-duplicator/internal/logging"
	"proxy-duplicator/internal/server"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println("dup", version)
	case "server":
		os.Exit(runMode(config.ModeServer, os.Args[2:]))
	case "client":
		os.Exit(runMode(config.ModeClient, os.Args[2:]))
	case "-h", "--help", "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func runMode(mode string, args []string) int {
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("c", "", "path to YAML config file")
	logLevel := fs.String("log-level", "", "override log level (debug|info|warn|error)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "-c <config file> is required")
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := cfg.Validate(mode); err != nil {
		fmt.Fprintln(os.Stderr, "error: invalid config:", err)
		return 1
	}
	if *logLevel != "" {
		cfg.Log.Level = *logLevel
		if err := cfg.Validate(mode); err != nil {
			fmt.Fprintln(os.Stderr, "error: invalid config:", err)
			return 1
		}
	}

	logger, closeLog, err := logging.New(cfg.Log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer func() { _ = closeLog }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var runErr error
	if mode == config.ModeServer {
		runErr = server.Run(ctx, cfg, logger)
	} else {
		runErr = client.Run(ctx, cfg, logger)
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		logger.Error("exited with error", "err", runErr)
		return 1
	}
	return 0
}

func usage(w *os.File) {
	fmt.Fprint(w, `dup — proxy-duplicator: duplicate traffic over N parallel SSH tunnels

Usage:
  dup server -c <file>   run the server side (dupd)
  dup client -c <file>   run the client side (dupc)
  dup version            print version
`)
}
