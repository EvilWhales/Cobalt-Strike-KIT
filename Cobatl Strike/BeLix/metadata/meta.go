package metadata

import (
	"belin/encrypt"
	"bytes"
	"encoding/binary"
	"fmt"
)

func New() *Metadata {
	m := new(Metadata)

	xxx := uint32(encrypt.RandomInt(100000, 999998))
	if xxx%2 != 0 {
		xxx = xxx+1
	}

	m.ClientId = xxx
	m.userName = "batata"
	m.hostName = "pits"
	m.procName = "batata"
	return m
}

/*
CompMetadata generally used to compile the firstblood and
define the const metadata.

return beaconID and Metadata
*/
func (m *Metadata) CompMetadata(aesKeyGlobB []byte) []byte {

	// 00 00 BE EF | magic number
	magicNum := 0xBEEF
	magicNumB := make([]byte, 4)
	binary.BigEndian.PutUint32(magicNumB, uint32(magicNum))

	// 00 00 00 00 | data size

	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | Key
	//aesKeyB := encrypt.RandomAESKey()
	// 00 00       | ANSI
	localANSIB := []byte{0x03, 0xa8}
	// 00 00       | OEM
	localOEMB := []byte{0x03, 0xa8}
	// 00 00 00 00 | Beacon ID
	clientIdB := make([]byte, 4)
	binary.BigEndian.PutUint32(clientIdB, m.ClientId)

	// 00 00 00 00 | PID
	procId := uint32(444)
	procIdB := make([]byte, 4)
	binary.BigEndian.PutUint32(procIdB, procId)
	// 00 00       | port
	sshPortB := make([]byte, 2)
	binary.BigEndian.PutUint16(sshPortB, uint16(0))
	// 00          | Flag (x32 x64)
	metaFlag := 4
	metaFlagB := make([]byte, 1)
	metaFlagB[0] = byte(metaFlag)
	// 00 00       | Version
	versionB := []byte{06, 01}
	// 00 00       |
	buildB := []byte{00, 00}
	// 00 00 00 00 | Prefix
	prefixB := []byte{00, 00, 00, 00}
	// 00 00 00 00 | Module Handler A ptr
	ptrMHAB := []byte{00, 00, 00, 00}
	// 00 00 00 00 | Proc Address ptr
	ptrPAB := []byte{00, 00, 00, 00}
	// 00 00 00 00 | Ip address
	ipAddress := 2316282048
	localIPB := make([]byte, 4)
	binary.BigEndian.PutUint32(localIPB, uint32(ipAddress))

	localInfo := fmt.Sprintf("%s\t%s\t%s", m.hostName, m.userName, m.procName)
	osInfoB := []byte(localInfo)

	md := [][]byte{
		aesKeyGlobB,
		localANSIB,
		localOEMB,
		clientIdB,
		procIdB,
		sshPortB,
		metaFlagB,
		versionB,
		buildB,
		prefixB,
		ptrMHAB,
		ptrPAB,
		localIPB,
		osInfoB,
	}

	metaInfoB := bytes.Join(md, []byte(""))

	metaInfolenB := make([]byte, 4)
	binary.BigEndian.PutUint32(metaInfolenB, uint32(len(metaInfoB)))

	pac := [][]byte{
		magicNumB,
		metaInfolenB,
		metaInfoB,
	}

	pacB := bytes.Join(pac, []byte(""))

	return pacB
}
