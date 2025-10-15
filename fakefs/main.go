package fakefs

import "log"

func main() {
	err := InitFakeFS()
	if err != nil {
		log.Fatal(err)
	}
}
