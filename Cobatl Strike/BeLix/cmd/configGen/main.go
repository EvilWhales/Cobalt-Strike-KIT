package main

import (
	"belin/keys"
	"encoding/base64"
	"flag"
	"fmt"
)

func main() {
	var keyfile = flag.String("k", "cobaltstrike.beacon_keys", "-k path/to/.cobaltstrike.beacon_keys")
	var host = flag.String("a", "0.0.0.0:80", "-a 0.0.0.0:80")
	flag.Parse()


	priv, publ, err := keys.Extract(*keyfile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	prPem := fmt.Sprintf(`
-----BEGIN RSA PRIVATE KEY-----
%s
-----END RSA PRIVATE KEY-----`,base64.StdEncoding.EncodeToString(priv))

	pbPem := fmt.Sprintf(`
-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----`,base64.StdEncoding.EncodeToString(publ))

	conf := fmt.Sprintf(`
package config

var (
RSAPUB = []byte(` + fmt.Sprint("`" + pbPem + "`") + `)
RSAPRV = []byte(` + fmt.Sprint("`" + prPem + "`") +`)


	HOST = "` + *host + `"
	GPTH = "/load"
	PPTH = "/submit.php?id="
	SLEP = 10000
	TOUT = 10
	CTYP = "application/json"
)
`)

	fmt.Print(conf)
}