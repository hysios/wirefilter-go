package main

import (
	"fmt"

	wirefliter "github.com/hysios/wirefilter"
)

func main() {
	scheme := wirefliter.CreateScheme()
	defer scheme.Close()

	fmt.Println("Hello World!")
}
