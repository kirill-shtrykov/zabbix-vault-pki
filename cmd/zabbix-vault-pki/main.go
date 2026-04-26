package main

import (
	"errors"
	"fmt"
	log "log/slog"
	"os"

	"github.com/kirill-shtrykov/zabbix-vault-pki/internal/monitor"
	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/config"
	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/vault"
)

const (
	minArgs       = 1
	minArgsExpiry = 2
)

var version = "dev"

func discover(service *monitor.Monitor, revoked bool) int {
	data, err := service.Discover(revoked)
	if err != nil {
		log.Error("failed to get LLD data", log.Any("error", err))

		return 1
	}

	_, err = os.Stdout.Write(data)
	if err != nil {
		log.Error("failed to write output", log.Any("error", err))

		return 1
	}

	return 0
}

func expiry(service *monitor.Monitor, sn string) int {
	ts, err := service.Expiry(sn)
	if err != nil {
		log.Error("failed to get certificate expiry", log.Any("error", err))

		return 1
	}

	_, err = fmt.Fprintf(os.Stdout, "%d\n", ts)
	if err != nil {
		log.Error("failed to write output", log.Any("error", err))

		return 1
	}

	return 0
}

func loadConfig() (config.Config, []string, bool) {
	cfg, args, err := config.Load()
	if err != nil {
		if errors.Is(err, config.ErrInvalidFlags) {
			usage()

			return config.Config{}, nil, false
		}

		log.Error("failed to read config", log.Any("error", err))

		return config.Config{}, nil, false
	}

	return cfg, args, true
}

func runCommand(args []string, service *monitor.Monitor, cfg config.Config) int {
	switch args[0] {
	case "discover":
		return discover(service, cfg.Revoked)
	case "expiry":
		if len(args) < minArgsExpiry {
			usage()

			return 1
		}

		return expiry(service, args[1])
	default:
		log.Error("unknown command", log.String("command", args[0]))

		return 1
	}
}

func run() int {
	cfg, args, ok := loadConfig()
	if !ok {
		return 1
	}

	if len(args) < minArgs {
		usage()

		return 1
	}

	if args[0] == "version" {
		fmt.Fprintln(os.Stdout, version)

		return 0
	}

	if err := cfg.Validate(); err != nil {
		log.Error("configuration error", log.Any("error", err))

		return 1
	}

	client, err := vault.NewClient(&cfg)
	if err != nil {
		log.Error("failed to create client", log.Any("error", err))

		return 1
	}

	service := monitor.New(client)

	return runCommand(args, service, cfg)
}

func usage() {
	const usageText = `Usage:
  zabbix-vault-pki version
  zabbix-vault-pki discover
  zabbix-vault-pki expiry <serial>

Global flags:
  -address
  -role-id
  -secret-id
  -config
  -revoked
  -tls-skip-verify
`
	os.Stdout.WriteString(usageText)
}

func main() {
	os.Exit(run())
}
