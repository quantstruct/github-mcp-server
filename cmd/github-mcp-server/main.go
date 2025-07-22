package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/github/github-mcp-server/internal/ghmcp"
	"github.com/github/github-mcp-server/pkg/github"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// These variables are set by the build process using ldflags.
var version = "version"
var commit = "commit"
var date = "date"

var (
	rootCmd = &cobra.Command{
		Use:     "server",
		Short:   "GitHub MCP Server",
		Long:    `A GitHub MCP server that handles various tools and resources.`,
		Version: fmt.Sprintf("Version: %s\nCommit: %s\nBuild Date: %s", version, commit, date),
	}

	stdioCmd = &cobra.Command{
		Use:   "stdio",
		Short: "Start stdio server",
		Long:  `Start a server that communicates via standard input/output streams using JSON-RPC messages.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			token := viper.GetString("personal_access_token")
			if token == "" {
				return errors.New("GITHUB_PERSONAL_ACCESS_TOKEN not set")
			}

			// If you're wondering why we're not using viper.GetStringSlice("toolsets"),
			// it's because viper doesn't handle comma-separated values correctly for env
			// vars when using GetStringSlice.
			// https://github.com/spf13/viper/issues/380
			var enabledToolsets []string
			if err := viper.UnmarshalKey("toolsets", &enabledToolsets); err != nil {
				return fmt.Errorf("failed to unmarshal toolsets: %w", err)
			}

			stdioServerConfig := ghmcp.StdioServerConfig{
				Version:              version,
				Host:                 viper.GetString("host"),
				Token:                token,
				EnabledToolsets:      enabledToolsets,
				DynamicToolsets:      viper.GetBool("dynamic_toolsets"),
				ReadOnly:             viper.GetBool("read-only"),
				ExportTranslations:   viper.GetBool("export-translations"),
				EnableCommandLogging: viper.GetBool("enable-command-logging"),
				LogFilePath:          viper.GetString("log-file"),
			}

			return ghmcp.RunStdioServer(stdioServerConfig)
		},
	}

	httpCmd = &cobra.Command{
		Use:   "http",
		Short: "Start HTTP server",
		Long:  `Start a server that communicates via HTTP using the Streamable-HTTP transport.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Check if we have either a personal access token or GitHub App credentials
			token := viper.GetString("personal_access_token")
			appID := viper.GetString("app_id")
			appPrivateKey := viper.GetString("app_private_key")
			enableGitHubAppAuth := viper.GetBool("enable_github_app_auth")

			if token == "" && (!enableGitHubAppAuth || appID == "" || appPrivateKey == "") {
				return errors.New("either GITHUB_PERSONAL_ACCESS_TOKEN or GitHub App credentials (GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY) must be set")
			}

			// If you're wondering why we're not using viper.GetStringSlice("toolsets"),
			// it's because viper doesn't handle comma-separated values correctly for env
			// vars when using GetStringSlice.
			// https://github.com/spf13/viper/issues/380
			var enabledToolsets []string
			if err := viper.UnmarshalKey("toolsets", &enabledToolsets); err != nil {
				return fmt.Errorf("failed to unmarshal toolsets: %w", err)
			}

			httpServerConfig := ghmcp.HttpServerConfig{
				Version:              version,
				Host:                 viper.GetString("host"),
				Token:                token,
				EnabledToolsets:      enabledToolsets,
				DynamicToolsets:      viper.GetBool("dynamic_toolsets"),
				ReadOnly:             viper.GetBool("read-only"),
				ExportTranslations:   viper.GetBool("export-translations"),
				EnableCommandLogging: viper.GetBool("enable-command-logging"),
				LogFilePath:          viper.GetString("log-file"),
				Address:              viper.GetString("http_address"),
				MCPPath:              viper.GetString("http_mcp_path"),
				EnableCORS:           viper.GetBool("http_enable_cors"),
				AppID:                appID,
				AppPrivateKey:        appPrivateKey,
				EnableGitHubAppAuth:  enableGitHubAppAuth,
				InstallationIDHeader: viper.GetString("installation_id_header"),
			}

			return ghmcp.RunHTTPServer(httpServerConfig)
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.SetVersionTemplate("{{.Short}}\n{{.Version}}\n")

	// Add global flags that will be shared by all commands
	rootCmd.PersistentFlags().StringSlice("toolsets", github.DefaultTools, "An optional comma separated list of groups of tools to allow, defaults to enabling all")
	rootCmd.PersistentFlags().Bool("dynamic-toolsets", false, "Enable dynamic toolsets")
	rootCmd.PersistentFlags().Bool("read-only", false, "Restrict the server to read-only operations")
	rootCmd.PersistentFlags().String("log-file", "", "Path to log file")
	rootCmd.PersistentFlags().Bool("enable-command-logging", false, "When enabled, the server will log all command requests and responses to the log file")
	rootCmd.PersistentFlags().Bool("export-translations", false, "Save translations to a JSON file")
	rootCmd.PersistentFlags().String("gh-host", "", "Specify the GitHub hostname (for GitHub Enterprise etc.)")

	// GitHub App authentication flags
	rootCmd.PersistentFlags().String("app-id", "", "GitHub App ID for authentication")
	rootCmd.PersistentFlags().String("app-private-key", "", "GitHub App private key for authentication")
	rootCmd.PersistentFlags().Bool("enable-github-app-auth", false, "Enable GitHub App authentication via custom headers")
	rootCmd.PersistentFlags().String("installation-id-header", "X-GitHub-Installation-ID", "Custom header name to read installation ID from")

	// HTTP server specific flags
	httpCmd.Flags().String("http-address", ":8080", "HTTP server address to bind to")
	httpCmd.Flags().String("http-mcp-path", "/mcp", "HTTP path for MCP endpoint")
	httpCmd.Flags().Bool("http-enable-cors", false, "Enable CORS for cross-origin requests")

	// Bind flags to viper
	_ = viper.BindPFlag("toolsets", rootCmd.PersistentFlags().Lookup("toolsets"))
	_ = viper.BindPFlag("dynamic_toolsets", rootCmd.PersistentFlags().Lookup("dynamic-toolsets"))
	_ = viper.BindPFlag("read-only", rootCmd.PersistentFlags().Lookup("read-only"))
	_ = viper.BindPFlag("log-file", rootCmd.PersistentFlags().Lookup("log-file"))
	_ = viper.BindPFlag("enable-command-logging", rootCmd.PersistentFlags().Lookup("enable-command-logging"))
	_ = viper.BindPFlag("export-translations", rootCmd.PersistentFlags().Lookup("export-translations"))
	_ = viper.BindPFlag("host", rootCmd.PersistentFlags().Lookup("gh-host"))
	_ = viper.BindPFlag("app_id", rootCmd.PersistentFlags().Lookup("app-id"))
	_ = viper.BindPFlag("app_private_key", rootCmd.PersistentFlags().Lookup("app-private-key"))
	_ = viper.BindPFlag("enable_github_app_auth", rootCmd.PersistentFlags().Lookup("enable-github-app-auth"))
	_ = viper.BindPFlag("installation_id_header", rootCmd.PersistentFlags().Lookup("installation-id-header"))
	_ = viper.BindPFlag("http_address", httpCmd.Flags().Lookup("http-address"))
	_ = viper.BindPFlag("http_mcp_path", httpCmd.Flags().Lookup("http-mcp-path"))
	_ = viper.BindPFlag("http_enable_cors", httpCmd.Flags().Lookup("http-enable-cors"))

	// Add subcommands
	rootCmd.AddCommand(stdioCmd)
	rootCmd.AddCommand(httpCmd)
}

func initConfig() {
	// Initialize Viper configuration
	viper.SetEnvPrefix("github")
	viper.AutomaticEnv()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
