package keys

import (
	//"bytes"
	//"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/jkeys089/jserial"
)

func decode(privEncB []interface{}) []byte {
	var encodedBytes []byte
	for _, v := range privEncB {
		if b, ok := v.(int8); ok {
			encodedBytes = append(encodedBytes, byte(b))
		} else {
			panic(fmt.Sprintf("invalid type in slice: %T", v))
		}
	}
	return encodedBytes
}

func Extract(file string) ([]byte, []byte, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	
	objects, err := jserial.ParseSerializedObject(b)
	if err != nil {
		return  nil, nil, err
	}
	
	m := objects[0].(map[string]interface{})
	m = m["array"].(map[string]interface{})
	m = m["extends"].(map[string]interface{})
	m = m["sleep.engine.types.ObjectValue"].(map[string]interface{})
	m = m["value"].(map[string]interface{})
	m = m["extends"].(map[string]interface{})
	m = m["java.security.KeyPair"].(map[string]interface{})
	
	priv := m["privateKey"].(map[string]interface{})
	privEncB := priv["encoded"].([]interface{})

	pub := m["publicKey"].(map[string]interface{})
	publEncB := pub["encoded"].([]interface{})

	privB := decode(privEncB)
	publB := decode(publEncB)

	fmt.Println()
	return  privB, publB, nil
}