package common

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
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

func PrintLinearHist(vals []int, base, step int, valType string) {
	valsSize := len(vals)
	starsMax := 40
	idxMax := -1
	idxMin := -1

	var valMax int
	for i := 0; i < valsSize; i++ {
		val := vals[i]
		if val > 0 {
			idxMax = i
			if idxMin < 0 {
				idxMin = i
			}
		}
		if val > valMax {
			valMax = val
		}
	}

	if idxMax < 0 {
		return
	}

	fmt.Printf("     %-13s : count     distribution\n", valType)
	for i := idxMin; i <= idxMax; i++ {
		val := vals[i]
		fmt.Printf("        %-10d : %-8d |", base+i*step, val)
		printStars(val, valMax, starsMax)
		fmt.Printf("|\n")
	}
}

type Partition struct {
	Name string
	Dev  int
}

type Partitions struct {
	Items []Partition
	Sz    int
}

func (p Partitions) GetByName(name string) *Partition {
	for _, item := range p.Items {
		item := item
		if item.Name == name {
			return &item
		}
	}
	return nil
}

func (p Partitions) GetByDev(dev int) *Partition {
	for _, item := range p.Items {
		item := item
		if item.Dev == dev {
			return &item
		}
	}
	return nil
}

func LoadPartitions() (*Partitions, error) {
	fdata, err := os.ReadFile("/proc/partitions")
	if err != nil {
		return nil, err
	}

	pts := &Partitions{}
	s := bufio.NewScanner(bytes.NewReader(fdata))
	for s.Scan() {
		line := s.Text()
		if line == "" || line[0] != ' ' {
			continue
		}
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) != 4 {
			continue
		}
		devmaj, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		devmin, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
		partName := parts[3]
		pts.Items = append(pts.Items, Partition{
			Name: partName,
			Dev:  mkdev(devmaj, devmin),
		})
		pts.Sz++
	}

	return pts, nil
}

const minOrBits = 20
const minOrMask = (1 << minOrBits) - 1

func mkdev(ma, mi int) int {
	return ((ma) << minOrBits) | (mi)
}
