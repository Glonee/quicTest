package main

import (
	"log"
	"os"
	"runtime"
	"runtime/pprof"
)

func saveProfile(filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	runtime.GC()
	if err = pprof.WriteHeapProfile(file); err != nil {
		log.Fatal(err)
	}
}
