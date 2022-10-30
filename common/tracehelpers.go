package common

import (
	"fmt"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func printStars(val int, valMax int, width int) {
	numStars := min(val, valMax) * width / valMax
	numSpaces := width - numStars
	needPlus := val > valMax

	for i := 0; i < numStars; i++ {
		fmt.Printf("*")
	}
	for i := 0; i < numSpaces; i++ {
		fmt.Printf(" ")
		if needPlus {
			fmt.Printf("+")
		}
	}
}

func PrintLog2Hist(vals []int, valType string) {
	valsSize := len(vals)
	starsMax := 40
	idxMax := -1

	var valMax int
	for i := 0; i < valsSize; i++ {
		val := vals[i]
		if val > 0 {
			idxMax = i
		}
		if val > valMax {
			valMax = val
		}
	}
	if idxMax < 0 {
		return
	}

	prefixWidth := 15
	suffixWidth := 29
	if idxMax <= 32 {
		prefixWidth = 5
		suffixWidth = 19
	}
	fmt.Printf("%*s%-*s : count    distribution\n", prefixWidth, "", suffixWidth, valType)

	var stars, width int
	if idxMax <= 32 {
		stars = starsMax
	} else {
		stars = starsMax / 2
	}

	for i := 0; i <= idxMax; i++ {
		low := (1 << (i + 1)) >> 1
		high := (1 << (i + 1)) - 1
		if low == high {
			low -= 1
		}
		val := vals[i]
		width = 20
		if idxMax <= 32 {
			width = 10
		}
		fmt.Printf("%*d -> %-*d : %-8d |", width, low, width, high, val)
		printStars(val, valMax, stars)
		fmt.Printf("|\n")
	}
}
