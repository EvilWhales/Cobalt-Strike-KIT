package encrypt

import (
	"time"

	"golang.org/x/exp/rand"
)

func RandomInt(min, max int) int {
	t := time.Now().UnixNano()
	rand.Seed(uint64(t))
	return min + rand.Intn(max-min)
}


func RandomAESKey() []byte {
	key := make([]byte,16)
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}
	return key
}