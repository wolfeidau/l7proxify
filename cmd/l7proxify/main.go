package main

// Copyright 2016 Mark Wolfe. All rights reserved.
// Use of this source code is governed by the MIT
// license which can be found in the LICENSE file.

import (
	"fmt"
	"os"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/apex/log/handlers/json"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wolfeidau/l7proxify"
)

var (
	// Version The version of the application (set by make file)
	Version = "UNKNOWN"

	cmdRoot = &cobra.Command{
		Use:   "l7proxify",
		Short: "L7 Proxy server",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {

			// colors and stderr
			log.SetHandler(cli.Default)

			err := viper.ReadInConfig() // Find and read the config file
			if err != nil {             // Handle errors reading the config file
				log.WithError(err).Error("failed to load config")
				os.Exit(-1)
			}

			if viper.GetBool("logging.json") {
				log.SetHandler(json.Default)
			}

			if viper.GetBool("debug") {
				log.SetLevel(log.DebugLevel)
			}

			//			viper.Debug()

			log.WithField("debug", viper.Get("debug")).Info("debug")
			log.WithField("json", viper.Get("logging.json")).Info("logging")
			log.WithField("localAddr", viper.Get("localAddr")).Info("listen")

			rules := viper.GetStringMap("rules")

			err = l7proxify.LoadRuleset(rules)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}

			l7proxify.ListenAndServe(viper.GetString("localAddr"), &l7proxify.TLSHandler{})
		},
	}

	rootOpts struct {
		Debug     bool
		LocalAddr string
	}
)

func init() {
	cmdRoot.PersistentFlags().BoolVar(&rootOpts.Debug, "debug", false, "Log debug information.")
	cmdRoot.PersistentFlags().StringVar(&rootOpts.LocalAddr, "localAddr", "localhost:13131", "Local listen address.")
	viper.BindPFlag("debug", cmdRoot.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("localAddr", cmdRoot.PersistentFlags().Lookup("localAddr"))
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/l7proxify/")
	viper.AddConfigPath("$HOME/.l7proxify")
	viper.AddConfigPath("./config")
	viper.SetConfigType("toml")
}

func main() {
	if err := cmdRoot.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
