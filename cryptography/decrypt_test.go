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

func TestDecryptEntireDirectory(t *testing.T) {
	serverConfig := cryptography.ServerConfig{
		PrivKey: cryptography.PrivKey{
			D: "47aa0a3bdd2d59a4cb2100241e080aea2dac4d679f7e4a851482d39827cf9e85",
		},
	}

	targetDir := filepath.Join(os.TempDir(), "test", "resources")
	decrypted := filepath.Join(targetDir, "notes.txt")
	encrypted := filepath.Join(targetDir, "_fck_notes.txt")

	assert.True(t, cryptography.Exists(encrypted))

	err := cryptography.DecryptDir(targetDir, serverConfig)
	assert.Nil(t, err)

	assert.True(t, cryptography.Exists(decrypted))
	assert.False(t, cryptography.Exists(encrypted))
}
