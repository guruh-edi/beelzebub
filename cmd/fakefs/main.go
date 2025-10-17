package main

import (
	"log"

	"github.com/mariocandela/beelzebub/v3/fakefs"
)

func main() {
	err := fakefs.InitFakeFS()
	if err != nil {
		log.Fatal(err)
	}
}
