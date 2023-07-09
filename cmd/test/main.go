package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var blah string
	flag.StringVar(&blah, "t", "", "blah")
	flag.Parse()

	fmt.Println("arg t = ", blah)
	env1 := os.Getenv("VAR1")
	env2 := os.Getenv("VAR2")

	fmt.Println("VAR1 =", env1)
	fmt.Println("VAR1 =", env2)
}
