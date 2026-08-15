package main

import (
	"log"
	"testing"
)

func TestRecover(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			log.Println(r)
		}
	}()

	panic("出错了")
}
