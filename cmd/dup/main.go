// Command dup is the proxy-duplicator: a duplication + failover tunnel
// multiplexer running over N parallel SSH (or plain TCP) tunnels.
//
// Usage:
//
//	dup server -c server.yaml
//	dup client -c client.yaml
//	dup version
//
// Without -c the config is auto-discovered next to the executable
// (then in the working directory): client.yaml / server.yaml.
// A bare `dup` (double-click) picks client.yaml first, else server.yaml.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"proxy-duplicator/internal/client"
	"proxy-duplicator/internal/config"
	"proxy-duplicator/internal/logging"
	"proxy-duplicator/internal/server"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		// Bare launch (e.g. double-click on Windows): auto-discover config.
		if path, mode := discoverConfig(""); path != "" {
			fmt.Fprintln(os.Stderr, "auto-loaded config:", path)
			os.Exit(runMode(mode, []string{"-c", path}))
		}
		usage(os.Stderr)
		pauseIfConsole("no client.yaml / server.yaml found next to the binary")
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
	cfgPath := fs.String("c", "", "path to YAML config file (default: auto-discover <mode>.yaml next to the binary)")
	logLevel := fs.String("log-level", "", "override log level (debug|info|warn|error)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" {
		if p, m := discoverConfig(mode); p != "" && m == mode {
			*cfgPath = p
			fmt.Fprintln(os.Stderr, "auto-loaded config:", p)
		} else {
			fmt.Fprintf(os.Stderr, "-c <config file> is required (or place %s.yaml next to the binary)\n", mode)
			return 2
		}
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

// discoverConfig finds a YAML config for the given mode ("", "client" or
// "server"). Search order: directory of the executable, then the working
// directory. For mode=="" (bare launch) client.yaml wins over server.yaml.
// Returns ("", "") when nothing was found or the found file is for the
// other mode.
func discoverConfig(mode string) (path, foundMode string) {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	return discoverConfigIn(dirs, mode)
}

// discoverConfigIn is the testable core: searches dirs (in order) for
// client.yaml / server.yaml according to mode. client.yaml wins when mode
// is empty and both exist in the same directory.
func discoverConfigIn(dirs []string, mode string) (path, foundMode string) {
	type cand struct {
		file string
		mode string
	}
	names := []cand{
		{"client.yaml", config.ModeClient},
		{"server.yaml", config.ModeServer},
	}
	if mode != "" {
		var only []cand
		for _, n := range names {
			if n.mode == mode {
				only = append(only, n)
			}
		}
		names = only
	}
	for _, d := range dirs {
		for _, n := range names {
			p := filepath.Join(d, n.file)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, n.mode
			}
		}
	}
	return "", ""
}

// pauseIfConsole waits for Enter so a double-clicked console window does not
// vanish before the user can read the message. No-op when stdin is not an
// interactive console (pipes, CI, services).
func pauseIfConsole(msg string) {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "%s. Press Enter to exit...", msg)
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func usage(w *os.File) {
	fmt.Fprint(w, `dup — proxy-duplicator: duplicate traffic over N parallel SSH tunnels

Usage:
  dup server -c <file>   run the server side (dupd)
  dup client -c <file>   run the client side (dupc)
  dup version            print version
  dup                    auto-discover client.yaml / server.yaml next to
                         the binary (client.yaml wins) and run it

Without -c, <mode>.yaml is looked up next to the executable, then in the
current directory.
`)
}
