package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	var outputDirectory string
	flag.StringVar(&outputDirectory, "output-directory", "/tmp", "the directory to put the compiled release tarball")
	flag.Parse()

	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		log.Fatal(err)
	}

	for _, arg := range flag.Args() {
		info, err := os.Stat(arg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(info.Name(), info.Size(), info.IsDir(), info.ModTime())
	}
}

func createReleaseManifest() {}
