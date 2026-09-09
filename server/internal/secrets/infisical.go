// Package secrets hydrates service configuration before listeners and database pools start.
package secrets

import (
	"context"
	"errors"
	infisical "github.com/infisical/go-sdk"
	"net/url"
	"os"
	"time"
)

type Config struct{ URL, ClientID, ClientSecret, ProjectID, Environment string }
type Fetch func(context.Context, Config) error

func Hydrate(getenv func(string) string, fetch Fetch) error {
	enabled := getenv("ENABLE_INFISICAL") == "true" || getenv("USE_INFISICAL") == "true" || getenv("INFISICAL_CLIENT_ID") != "" || getenv("INFISICAL_CLIENT_SECRET") != ""
	if !enabled {
		return nil
	}
	cfg := Config{URL: getenv("INFISICAL_API_URL"), ClientID: getenv("INFISICAL_CLIENT_ID"), ClientSecret: getenv("INFISICAL_CLIENT_SECRET"), ProjectID: getenv("INFISICAL_PROJECT_ID"), Environment: getenv("INFISICAL_ENV")}
	if cfg.URL == "" {
		cfg.URL = "https://infisical.synehq.com"
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return errors.New("Infisical requires an HTTPS service URL")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.ProjectID == "" || cfg.Environment == "" {
		return errors.New("Infisical bootstrap configuration incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := fetch(ctx, cfg); err != nil {
		return errors.New("Infisical hydration failed")
	}
	return nil
}
func Load() error {
	return Hydrate(os.Getenv, func(ctx context.Context, cfg Config) error {
		client := infisical.NewInfisicalClient(ctx, infisical.Config{SiteUrl: cfg.URL, AutoTokenRefresh: false})
		if _, err := client.Auth().UniversalAuthLogin(cfg.ClientID, cfg.ClientSecret); err != nil {
			return err
		}
		_, err := client.Secrets().List(infisical.ListSecretsOptions{ProjectID: cfg.ProjectID, Environment: cfg.Environment, AttachToProcessEnv: true})
		return err
	})
}
