package main

import (
	"fmt"
)

func main() {
	a := make([]int, 12)
	a = append(a, 11)
	fmt.Printf("%v \n", a)
	fmt.Errorf("")
}
