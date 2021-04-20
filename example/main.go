package main

import (
	"log"

	"github.com/hysios/wirefilter"
)

func main() {
	scheme := wirefilter.CreateScheme()
	defer scheme.Close()

	filter, err := scheme.ParerFilter(`http.method eq "POST" && not http.ua matches "(googlebot|facebook)" && port in {80 443}`)
	if err != nil {
		log.Printf("error %s", err)
	}
	log.Printf("% #v", filter)
}
