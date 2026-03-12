package main

import (
	"flag"
	"fmt"
	log "log/slog"
	"os"

	"github.com/kirill-shtrykov/zabbix-vault-pki/internal/monitor"
	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/config"
	"github.com/kirill-shtrykov/zabbix-vault-pki/pkg/vault"
)

var version = "dev"

func discover(service *monitor.Monitor) int {
	data, err := service.Discovery()
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

func run() int {
	cfg, err := config.Load()
	if err != nil {
		log.Error("failed to read config", log.Any("error", err))

		return 1
	}

	args := flag.Args()
	if len(args) == 0 {
		usage()

		return 1
	}

	client, err := vault.NewClient(cfg)
	if err != nil {
		log.Error("failed to create client", log.Any("error", err))

		return 1
	}

	service := monitor.New(client)

	switch args[0] {
	case "version":
		log.Info(version)

		return 0
	case "discover":
		return discover(service)

	case "expiry":
		const minArgsExpiry = 2

		if len(args) < minArgsExpiry {
			log.Error("serial number required")

			return 1
		}

		return expiry(service, args[1])

	default:
		log.Error("unknown command", log.String("command", args[0]))

		return 1
	}
}

func usage() {
	const usageText = `Usage:
  zabbix-vault-pki discover
  zabbix-vault-pki expiry <serial>

Global flags:
  -address
  -role-id
  -secret-id
  -config
`
	os.Stdout.WriteString(usageText)
}

func main() {
	os.Exit(run())
}
