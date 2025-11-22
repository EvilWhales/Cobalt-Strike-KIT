package main

import (
	"belin/keys"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Provide the key file: main.go path/to/.cobaltstrike.beacon_keys")
		return
	}

	priv, publ, err := keys.Extract(os.Args[1])
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	base64.StdEncoding.EncodeToString(publ)

	prPem := fmt.Sprintf(`
-----BEGIN RSA PRIVATE KEY-----
%s
-----END RSA PRIVATE KEY-----`,base64.StdEncoding.EncodeToString(priv))

	pbPem := fmt.Sprintf(`
-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----`,base64.StdEncoding.EncodeToString(publ))

	fmt.Println(prPem,pbPem)
}