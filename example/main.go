package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/javi11/rarlist"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <first-volume>.part1.rar", os.Args[0])
	}
	first := os.Args[1]

	// aggregated files JSON
	files, err := rarlist.ListFiles(first)
	if err != nil {
		log.Fatalf("error aggregating files: %v", err)
	}
	b, _ := json.MarshalIndent(files, "", "  ")
	fmt.Println(string(b))
}
