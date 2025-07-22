package ghmcp

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"
)

type HttpServerConfig struct {
	// Version of the server
	Version string

	// GitHub Host to target for API requests (e.g. github.com or github.enterprise.com)
	Host string

	// GitHub Token to authenticate with the GitHub API
	Token string

	// EnabledToolsets is a list of toolsets to enable
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#tool-configuration
	EnabledToolsets []string

	// Whether to enable dynamic toolsets
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#dynamic-tool-discovery
	DynamicToolsets bool

	// ReadOnly indicates if we should only register read-only tools
	ReadOnly bool

	// ExportTranslations indicates if we should export translations
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#i18n--overriding-descriptions
	ExportTranslations bool

	// EnableCommandLogging indicates if we should log commands
	EnableCommandLogging bool

	// Path to the log file if not stderr
	LogFilePath string

	// HTTP server configuration
	Address string

	// MCP endpoint path (defaults to "/mcp")
	MCPPath string

	// Enable CORS for cross-origin requests
	EnableCORS bool

	// GITHUB APP ID
	AppID string

	// GITHUB APP PRIVATE KEY
	AppPrivateKey string

	// Whether to enable GitHub App authentication via headers
	EnableGitHubAppAuth bool

	// Custom header name to read installation ID from (defaults to "X-GitHub-Installation-ID")
	InstallationIDHeader string
}

const installationContextKey = "installation_id"

// RunHTTPServer is not concurrent safe.
func RunHTTPServer(cfg HttpServerConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	t, dumpTranslations := translations.TranslationHelper()

	mcpCfg := MCPServerConfig{
		Version:              cfg.Version,
		Host:                 cfg.Host,
		Token:                cfg.Token,
		EnabledToolsets:      cfg.EnabledToolsets,
		DynamicToolsets:      cfg.DynamicToolsets,
		ReadOnly:             cfg.ReadOnly,
		Translator:           t,
		AppID:                cfg.AppID,
		AppPrivateKey:        cfg.AppPrivateKey,
		EnableGitHubAppAuth:  cfg.EnableGitHubAppAuth,
		InstallationIDHeader: cfg.InstallationIDHeader,
	}

	ghServer, err := NewMCPServer(mcpCfg)
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	httpServer := server.NewStreamableHTTPServer(ghServer)

	logrusLogger := logrus.New()
	if cfg.LogFilePath != "" {
		file, err := os.OpenFile(cfg.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		logrusLogger.SetLevel(logrus.DebugLevel)
		logrusLogger.SetOutput(file)
	} else {
		logrusLogger.SetLevel(logrus.InfoLevel)
	}

	if cfg.Address == "" {
		cfg.Address = ":8080"
	}
	if cfg.MCPPath == "" {
		cfg.MCPPath = "/mcp"
	}
	if cfg.InstallationIDHeader == "" {
		cfg.InstallationIDHeader = "X-GitHub-Installation-ID"
	}

	mux := http.NewServeMux()
	var handler http.Handler = httpServer

	// Apply middlewares in the correct order: CORS first, then auth
	if cfg.EnableCORS {
		handler = corsMiddleware(handler)
	}
	if cfg.EnableGitHubAppAuth {
		handler = authMiddleware(handler, cfg.InstallationIDHeader, logrusLogger)
	}

	mux.Handle(cfg.MCPPath, handler)

	srv := &http.Server{
		Addr:    cfg.Address,
		Handler: mux,
	}

	if cfg.ExportTranslations {
		dumpTranslations()
	}

	errC := make(chan error, 1)
	go func() {
		logrusLogger.Infof("Starting HTTP server on %s", cfg.Address)
		logrusLogger.Infof("MCP endpoint available at http://localhost%s%s", cfg.Address, cfg.MCPPath)
		if cfg.EnableGitHubAppAuth {
			logrusLogger.Infof("GitHub App authentication enabled with header: %s", cfg.InstallationIDHeader)
		}
		errC <- srv.ListenAndServe()
	}()

	_, _ = fmt.Fprintf(os.Stderr, "GitHub MCP Server running on HTTP at %s\n", cfg.Address)
	_, _ = fmt.Fprintf(os.Stderr, "MCP endpoint: http://localhost%s%s\n", cfg.Address, cfg.MCPPath)
	if cfg.EnableGitHubAppAuth {
		_, _ = fmt.Fprintf(os.Stderr, "GitHub App authentication enabled with header: %s\n", cfg.InstallationIDHeader)
	}

	select {
	case <-ctx.Done():
		logrusLogger.Infof("shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logrusLogger.Errorf("error during server shutdown: %v", err)
		}
	case err := <-errC:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("error running server: %w", err)
		}
	}

	return nil
}

// corsMiddleware adds CORS headers to allow cross-origin requests
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Host, Origin, Referer, User-Agent")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware extracts installation IDs from custom headers and adds them to the request context
func authMiddleware(next http.Handler, headerName string, logger *logrus.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		installationIDStr := r.Header.Get(headerName)
		if installationIDStr == "" {
			next.ServeHTTP(w, r)
			return
		}

		installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
		if err != nil {
			logger.Warnf("Invalid installation ID format in header %s", headerName)
			http.Error(w, "Invalid installation ID format", http.StatusBadRequest)
			return
		}

		if installationID <= 0 {
			logger.Warnf("Invalid installation ID value: %d", installationID)
			http.Error(w, "Invalid installation ID value", http.StatusBadRequest)
			return
		}

		ctx := context.WithValue(r.Context(), installationContextKey, installationID)
		r = r.WithContext(ctx)

		if logger.GetLevel() == logrus.DebugLevel {
			logger.Debugf("Authenticated request with installation ID %d", installationID)
		} else {
			logger.Debug("Request authenticated with GitHub App installation")
		}

		next.ServeHTTP(w, r)
	})
}
