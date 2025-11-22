package encrypt

import "crypto/rsa"

type Enc struct {
	IV []byte
	GlobalKey []byte
	AesKey    []byte
	HmacKey   []byte

	RsaPubl *rsa.PublicKey
	RsaPriv *rsa.PrivateKey
}