package common

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"sort"
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

type Ksym struct {
	Name string
	Addr uint64
}

type Ksyms struct {
	Syms []Ksym
	// Strs string
}

func LoadKsyms() (*Ksyms, error) {
	fdata, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return nil, err
	}

	ksyms := &Ksyms{}
	s := bufio.NewScanner(bytes.NewReader(fdata))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			return nil, err
		}
		name := fields[2]
		ksyms.Syms = append(ksyms.Syms, Ksym{
			Name: name,
			Addr: addr,
		})
	}

	syms := ksyms.Syms
	sort.Slice(syms, func(i, j int) bool {
		if syms[i].Addr == syms[j].Addr {
			return syms[i].Name >= syms[j].Name
		}
		return syms[i].Addr >= syms[j].Addr
	})

	ksyms.Syms = syms
	return ksyms, nil
}

func (k *Ksyms) MapAddr(addr uint64) *Ksym {
	syms := k.Syms
	i := sort.Search(len(syms), func(i int) bool {
		return syms[i].Addr <= addr
	})

	// fmt.Printf("%d ? %d\n", addr, i)
	if i < len(syms) {
		v := syms[i]
		return &v
	}
	return nil
}

func (k *Ksyms) GetSymbol(name string) *Ksym {
	for _, v := range k.Syms {
		v := v
		if v.Name == name {
			return &v
		}
	}
	return nil
}
