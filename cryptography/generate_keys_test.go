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
	"math/big"
	"path/filepath"
	"testing"

	"github.com/gustavohenrique/ransomware/cryptography"

	"github.com/stretchr/testify/assert"
)

func TestGenerateECDSAPrivateKey(t *testing.T) {
	key, _ := cryptography.GenerateECDSAPrivateKey()
	assert.True(t, len(key.D.String()) > 0)
}

func TestGetExistingPrivateKey(t *testing.T) {
	expected := "47aa0a3bdd2d59a4cb2100241e080aea2dac4d679f7e4a851482d39827cf9e85"
	basedir, _ := filepath.Abs("../")
	privateKeyFile := filepath.Join(basedir, "test", "resources", "private.key")
	ecdsaPrivKey, _ := cryptography.GenerateECDSAPrivateKey()
	privKey := cryptography.GetOrCreatePrivKey(ecdsaPrivKey, privateKeyFile)
	assert.Equal(t, expected, privKey.D)
}

func TestGetExistingPublicKey(t *testing.T) {
	expectedX := "8e6859e0356e8ae0d6f97a7ea778baac6bc4260b3d6a05673df74b92eb5e07bf"
	expectedY := "89f9e0a014f0219c42ee172494ec5793f4f263cb59e9d08b309be57b99fc85a5"
	basedir, _ := filepath.Abs("../")
	publicKeyFile := filepath.Join(basedir, "test", "resources", "public.key")
	ecdsaPrivKey, _ := cryptography.GenerateECDSAPrivateKey()
	pubKey := cryptography.GetOrCreatePubKey(ecdsaPrivKey, publicKeyFile)
	assert.Equal(t, expectedX, pubKey.X)
	assert.Equal(t, expectedY, pubKey.Y)
}

func TestConvertBigintToHex(t *testing.T) {
	i := new(big.Int)
	i.SetString("44673320128741735993998272570414652813472481189388609111363855118567748460998", 10)
	expected := "62c43401ee7b64e75ce174d4c3e22972be9d32b511e15256287562af4aa8e1c6"
	h := cryptography.ToHex(i)
	assert.Equal(t, expected, h)
}

func TestConvertBigintToHexWhenTheNumberIsEmpty(t *testing.T) {
	i := new(big.Int)
	i.SetString("", 10)
	expected := "00"
	h := cryptography.ToHex(i)
	assert.Equal(t, expected, h)
}
