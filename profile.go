package main

import (
	"log"
	"os"
	"runtime"
	"runtime/pprof"
)

func saveProfile(profile, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	if profile == "heap" {
		runtime.GC()
	}
	if err = pprof.Lookup(profile).WriteTo(file, 0); err != nil {
		log.Fatal(err)
	}
}
