package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"threatgraph/backend/internal/api"
	"threatgraph/backend/internal/enrichment"
	"threatgraph/backend/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	port := env("PORT", "8080")
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		logger.Error("PORT must be numeric", "error", err)
		os.Exit(1)
	}
	if portNumber < 1 || portNumber > 65535 {
		logger.Error("PORT must be between 1 and 65535")
		os.Exit(1)
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(1)
	}
	scorer, err := api.NewHTTPScorer(env("SCORER_URL", "http://localhost:8000"), 8*time.Second)
	if err != nil {
		logger.Error("invalid SCORER_URL", "error", err)
		os.Exit(1)
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStartup()
	repository := store.NewPostgres(db)
	if err := repository.Ping(startupCtx); err != nil {
		logger.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	if err := repository.Migrate(startupCtx); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}

	dnsService, err := enrichment.ConfiguredService(repository, os.Getenv)
	if err != nil {
		logger.Error("invalid DNS configuration", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           api.NewHandler(scorer, repository, logger).WithDNS(dnsService).WithDNSScoring(scorer, repository).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("API listening", "port", port)
		serverErrors <- server.ListenAndServe()
	}()

	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server stopped", "error", err)
			os.Exit(1)
		}
	case <-shutdownCtx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("graceful HTTP shutdown failed", "error", err)
			_ = server.Close()
		}
		logger.Info("API stopped")
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
