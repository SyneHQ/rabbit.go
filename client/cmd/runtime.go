package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"rabbit.go/client/internal/tunnel"
)

type runtimeConnectionFile struct {
	Version       int                        `json:"version"`
	ServerAddress string                     `json:"serverAddress"`
	CAFile        string                     `json:"caFile"`
	ServerName    string                     `json:"serverName"`
	HelperAddress string                     `json:"helperAddress"`
	Registration  tunnel.RuntimeRegistration `json:"registration"`
}

func readRuntimeConnectionFile(path string) (runtimeConnectionFile, error) {
	var config runtimeConnectionFile
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return config, errors.New("runtime connection file must be a private regular file, at most 8192 bytes")
	}
	file, err := os.Open(path)
	if err != nil {
		return config, errors.New("cannot read runtime connection file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return config, errors.New("runtime connection file changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data) > 8192 {
		return config, errors.New("invalid runtime connection file")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || config.Version != 2 || config.ServerAddress == "" {
		return config, errors.New("invalid runtime connection configuration")
	}
	return config, nil
}

func init() {
	var path string
	command := &cobra.Command{Use: "runtime-connect", Short: "Connect an enrolled notebook helper through private Rabbit TLS routing", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := readRuntimeConnectionFile(path)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			client := tunnel.RuntimeClient{Dial: tunnel.TunnelClientConfig{ServerAddress: config.ServerAddress, CAFile: config.CAFile, ServerName: config.ServerName}, Registration: config.Registration, HelperAddress: config.HelperAddress}
			err = client.Run(ctx)
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}}
	command.Flags().StringVar(&path, "connection-file", "", "Private runtime connection JSON file (mode 0600)")
	_ = command.MarkFlagRequired("connection-file")
	rootCmd.AddCommand(command)
}
