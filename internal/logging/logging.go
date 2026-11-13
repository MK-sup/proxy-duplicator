package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"proxy-duplicator/internal/config"
)

// New builds the process logger from config. Returns the logger and a closer
// for an optional log file (closer is never nil).
func New(cfg config.LogConfig) (*slog.Logger, func() error, error) {
	var w io.Writer = os.Stdout
	closer := func() error { return nil }
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file: %w", err)
		}
		w = f
		closer = f.Close
	}

	var level slog.Level
	switch cfg.Level {
	case config.LevelDebug:
		level = slog.LevelDebug
	case config.LevelWarn:
		level = slog.LevelWarn
	case config.LevelError:
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.Format == config.FormatJSON {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h), closer, nil
}
