package main

import (
	"os"

	"github.com/elastic/beats/libbeat/beat"

	"github.com/0xStormEye/otilio/beater"
)

func main() {
	err := beat.Run("otilio", "", beater.New)
	if err != nil {
		os.Exit(1)
	}
}
