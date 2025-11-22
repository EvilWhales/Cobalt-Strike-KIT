package main

import (
	"belin/internal"
	"log"
)

func main(){
	err := internal.Init()
	if err != nil {
		log.Println(err.Error())
	}
}