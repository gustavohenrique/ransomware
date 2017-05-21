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
	"fmt"
	"io/ioutil"
	"os"
)

const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>You are victim of a ransomware</title>
</head>
<body>
  <h1>Important message</h1>
  <p>The files into the directory %s was encrypted.<br/>
  Good news! You don't need to pay anything to get your files again.</p>
</body>
</html>`

func GenerateRansomwareHtmlPage(htmlFile string, targetDir string) (err error) {
	if _, err := os.Stat(htmlFile); os.IsNotExist(err) {
		content := fmt.Sprintf(HTML_TEMPLATE, targetDir)
		err = ioutil.WriteFile(htmlFile, []byte(content), 0644)
	}
	return err
}
