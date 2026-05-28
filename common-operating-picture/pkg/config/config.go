package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/creasty/defaults"
	validator "github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
	"github.com/virtru-corp/dsp-cop/pkg/logger"
)

const AppName = "dsp-cop"

const validatorErrMsg = `

#######################
# NOTE: Validator error messages are in the format of the Go struct field name.
# 
# These can be transformed to the config key by converting to snake_case and replacing "." with "_".
# Examples:
#  - "OIDCClientIdForServer" corresponds to the config key "oidc_client_id_for_server"
#  - "Service.GrpcPort" corresponds to the config key "service_grpc_port"
#  - etc
#######################

`

// DataSourcePlugin selects which database backend to use.
type DataSourcePlugin string

const (
	// DataSourcePluginPostgres connects directly to PostgreSQL (default).
	DataSourcePluginPostgres DataSourcePlugin = "postgres"
	// DataSourcePluginTrino connects via the TDF-Trino query engine.
	DataSourcePluginTrino DataSourcePlugin = "trino"
)

// TrinoConfig holds connection settings for the Trino data source plugin.
type TrinoConfig struct {
	// URL is the Trino server base URL
	URL string `mapstructure:"url"`
	// Catalog is the Trino catalog to query
	Catalog string `mapstructure:"catalog" default:"tdf_postgresql"`
	// Schema is the Trino schema to use
	Schema string `mapstructure:"schema" default:"public"`
	// User is the Trino user for authentication
	User string `mapstructure:"user" default:"admin"`
	// SSLCertPath is the path to a PEM CA certificate to trust for HTTPS connections.
	// Required when using https:// and the server uses a self-signed or private CA cert.
	SSLCertPath string `mapstructure:"ssl_cert_path"`
	// InsecureSkipVerify skips TLS certificate verification.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
	// PolicySigningSecret is the HMAC-SHA256 key used to sign and verify tdf_policy rows.
	// Must match tdf.policy-signing-secret in the Trino catalog properties file.
	PolicySigningSecret string `mapstructure:"policy_signing_secret"`
}

// DataSourceConfig selects which database plugin to use and holds its settings.
type DataSourceConfig struct {
	// Plugin selects the data source backend: "postgres" (default) or "trino"
	Plugin DataSourcePlugin `mapstructure:"plugin" default:"postgres"`
	// Trino holds connection settings when Plugin is "trino"
	Trino TrinoConfig `mapstructure:"trino"`
}

type Config struct {
	////////////////////////
	//// Required
	////////////////////////

	// DataSource selects the database backend (postgres or trino) and its connection settings.
	// When plugin is "postgres" (default), db_url is required.
	// When plugin is "trino", data_source.trino.url is required.
	DataSource DataSourceConfig `mapstructure:"data_source"`

	// DB connection string and pool settings — required when data_source.plugin is "postgres".
	// https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
	// Pool settings https://pkg.go.dev/github.com/jackc/pgx/v5@v5.5.5/pgxpool#ParseConfig
	DBUrl string `mapstructure:"db_url"`

	// DSP platform endpoint
	PlatformEndpoint string `mapstructure:"platform_endpoint" validate:"required"`

	// OIDC configuration for the COP server
	OIDCClientIdForServer     string `mapstructure:"oidc_client_id_for_server" validate:"required"`
	OIDCClientSecretForServer string `mapstructure:"oidc_client_secret_for_server" validate:"required"`

	// OIDC configuration for the web based password flow
	OIDCClientIdForWebPasswordFlow string `mapstructure:"oidc_client_id_for_web_password_flow" validate:"required"`

	// @deprecated KAS url which will be replaced by fetching from DSP wellknown
	DeprecatedKASUrl string `mapstructure:"deprecated_kas_url"`

	// @deprecated IDP url which will be replaced by fetching from DSP wellknown
	DeprecatedIdpUrl string `mapstructure:"deprecated_idp_url"`

	////////////////////////
	//// Optional
	////////////////////////

	// Basic auth credentials to gate the entire application (browser prompt).
	// If both are set, all requests require HTTP Basic Auth before anything loads.
	BasicAuthUsername string `mapstructure:"basic_auth_username"`
	BasicAuthPassword string `mapstructure:"basic_auth_password"`

	LogLevel string `mapstructure:"log_level" default:"DEBUG"`

	Service struct {
		// The public host and port is used by the web interface to connect to the server. In many
		// environments this will not be the same as the hostname and port the server is listening on.
		PublicServerHost string `mapstructure:"public_server_host"`
		PublicStaticHost string `mapstructure:"public_static_host"`

		GrpcPort         string `mapstructure:"grpc_port" default:"5002"`
		GrpcWriteTimeout int    `mapstructure:"grpc_write_timeout" default:"60"`
		GrpcReadTimeout  int    `mapstructure:"grpc_read_timeout" default:"60"`
		GrpcIdleTimeout  int    `mapstructure:"grpc_idle_timeout" default:"300"`

		StaticPort         string `mapstructure:"static_port" default:"5001"`
		StaticWriteTimeout int    `mapstructure:"static_write_timeout" default:"60"`
		StaticReadTimeout  int    `mapstructure:"static_read_timeout" default:"60"`

		StreamHeartbeatInterval int `mapstructure:"stream_heartbeat_interval" default:"5"`

		// CORS configuration (an empty string will default to the hostname)
		CORSOrigin string `mapstructure:"cors_origin" default:"*"`

		// TLS configuration
		TLS struct {
			Enabled  bool   `mapstructure:"enabled" default:"true"`
			CertFile string `mapstructure:"cert_file"`
			KeyFile  string `mapstructure:"key_file"`
		} `mapstructure:"tls"`
	} `mapstructure:"service"`

	// UI configuration
	UI struct {
		// Tile server URL for the map
		TileServerURL string `mapstructure:"tile_server_url" default:"https://tile.openstreetmap.org/{z}/{x}/{y}.png"`

		// Override TDF3/ZTDF default and encrypt forms as NanoTDFs
		FormSubmitNanoTDF bool `mapstructure:"form_submit_nano_tdf" default:"true"`
	}
}

func New() (*Config, error) {
	c := &Config{}

	v := viper.NewWithOptions(viper.WithLogger(slog.Default()))

	v.SetConfigName("config")
	v.SetConfigType("yaml")

	// Config search paths (see https://clig.dev/#configuration)
	v.AddConfigPath("/etc/" + AppName + "/")    // System-wide config: /etc/dsp-cop/config.yaml
	v.AddConfigPath("$HOME/.config/" + AppName) // User-level via XDG-spec: ~/.config/dsp-cop/config.yaml
	v.AddConfigPath(".")                        // Project-level config: ./config.yaml

	// Environment variables
	v.SetEnvPrefix(AppName)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// AppName is "dsp-cop", so Viper's automatic prefix becomes "DSP-COP_" (with hyphen).
	// Shell/Docker env vars cannot have hyphens, so the automatic lookup for
	// DSP-COP_DATA_SOURCE_TRINO_POLICY_SIGNING_SECRET silently fails.
	// BindEnv maps the underscore-safe name the docker-compose actually sets.
	_ = v.BindEnv("data_source.trino.policy_signing_secret", "DSP_COP_DATA_SOURCE_TRINO_POLICY_SIGNING_SECRET")

	// Read the config file
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fatal error config file: %w", err)
	}

	if err := defaults.Set(c); err != nil {
		return nil, fmt.Errorf("fatal error setting defaults: %w", err)
	}

	if err := v.Unmarshal(c); err != nil {
		return nil, fmt.Errorf("fatal error unmarshalling config: %w", err)
	}

	// Derive defaults from platform_endpoint so the hostname is only configured once
	if err := c.deriveDefaults(); err != nil {
		return nil, fmt.Errorf("fatal error deriving defaults: %w", err)
	}

	validate := validator.New()
	if err := validate.Struct(c); err != nil {
		fmt.Print(validatorErrMsg)
		return nil, fmt.Errorf("fatal error validating config: %w", err)
	}

	// Validate plugin-specific required fields
	switch c.DataSource.Plugin {
	case DataSourcePluginPostgres, "":
		c.DataSource.Plugin = DataSourcePluginPostgres
		if c.DBUrl == "" {
			return nil, fmt.Errorf("db_url is required when data_source.plugin is %q", DataSourcePluginPostgres)
		}
	case DataSourcePluginTrino:
		if c.DataSource.Trino.URL == "" {
			return nil, fmt.Errorf("data_source.trino.url is required when data_source.plugin is %q", DataSourcePluginTrino)
		}
	default:
		return nil, fmt.Errorf("data_source.plugin must be %q or %q, got %q", DataSourcePluginPostgres, DataSourcePluginTrino, c.DataSource.Plugin)
	}

	// Set the CORS origin if it's empty
	if c.Service.CORSOrigin == "" {
		c.Service.CORSOrigin = c.Service.PublicStaticHost
	}

	// Set the log level from the config so we can log the config
	logger.SetLevel(c.LogLevel)

	slog.Info("config loaded", slog.String("file", v.ConfigFileUsed()))
	slog.Debug("config data", slog.Any("config", c))

	return c, nil
}

// deriveDefaults fills in empty config values by deriving them from platform_endpoint.
// This allows the hostname to be configured once rather than repeated across many fields.
func (c *Config) deriveDefaults() error {
	if c.PlatformEndpoint == "" {
		return nil
	}

	parsed, err := url.Parse(c.PlatformEndpoint)
	if err != nil {
		return fmt.Errorf("failed to parse platform_endpoint: %w", err)
	}

	hostname := parsed.Hostname()
	scheme := parsed.Scheme

	if c.DeprecatedKASUrl == "" {
		c.DeprecatedKASUrl = c.PlatformEndpoint + "/kas"
	}
	if c.DeprecatedIdpUrl == "" {
		c.DeprecatedIdpUrl = scheme + "://" + hostname + ":8443/auth/realms/opentdf"
	}
	if c.Service.PublicServerHost == "" {
		c.Service.PublicServerHost = scheme + "://" + hostname + ":" + c.Service.GrpcPort
	}
	if c.Service.PublicStaticHost == "" {
		c.Service.PublicStaticHost = scheme + "://" + hostname + ":" + c.Service.StaticPort
	}
	if c.Service.TLS.CertFile == "" {
		c.Service.TLS.CertFile = "/dsp-keys/" + hostname + ".pem"
	}
	if c.Service.TLS.KeyFile == "" {
		c.Service.TLS.KeyFile = "/dsp-keys/" + hostname + ".key.pem"
	}

	return nil
}
