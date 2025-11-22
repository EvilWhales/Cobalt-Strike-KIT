package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const HmacHashLen = 16

func New(rsapubl, rsapriv []byte) (*Enc, error) {
	e := new(Enc)

	// Config pub key
	blockPub, _ := pem.Decode(rsapubl)
	if blockPub == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, err
	}
	e.RsaPubl = pubInterface.(*rsa.PublicKey)

	// Config priv key
	blockPriv, _ := pem.Decode(rsapriv)
	if blockPub == nil {
		return nil, errors.New("private key error")
	}
	privInterface, err := x509.ParsePKCS8PrivateKey(blockPriv.Bytes)
	if err != nil {
		return nil, err
	}
	e.RsaPriv = privInterface.(*rsa.PrivateKey)

	// Config symmetric key
	e.GlobalKey = RandomAESKey()
	sha256hash := sha256.Sum256(e.GlobalKey)
	e.AesKey  = sha256hash[:16]
	e.HmacKey = sha256hash[16:]
	e.IV = []byte("abcdefghijklmnop")

	return e, nil
}

func (e *Enc) RsaEnc(data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, e.RsaPubl, data)
}

func (e *Enc) RsaDec(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15 (rand.Reader, e.RsaPriv, data)
}


func PaddingWithA(rawData []byte) []byte {
	newBuf := bytes.NewBuffer(rawData)
	step := 16
	for pad := newBuf.Len() % step; pad < step; pad++  {
		newBuf.Write([]byte("A"))
	}
	return newBuf.Bytes()
}

func (e *Enc)AesCBCEncrypt(rawData,key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	rawData = PaddingWithA(rawData)
	cipherText := make([]byte,blockSize+len(rawData))
	mode := cipher.NewCBCEncrypter(block, e.IV)
	mode.CryptBlocks(cipherText[blockSize:],rawData)
	return cipherText, nil
}

func (e *Enc)AesCBCDecrypt(encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()
	if len(encryptData) < blockSize {
		return nil, errors.New("ciphertext too short")
	}
	if len(encryptData) % blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, e.IV)
	mode.CryptBlocks(encryptData, encryptData)
	return encryptData,nil
}

func (e *Enc)HmacHash(encrytedBytes []byte) []byte {
	hmacEntry := hmac.New(sha256.New, e.HmacKey)
	hmacEntry.Write(encrytedBytes)
	return hmacEntry.Sum(nil)[:16]
}