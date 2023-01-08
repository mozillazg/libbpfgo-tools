package common

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
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
	syms []Ksym
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
		ksyms.syms = append(ksyms.syms, Ksym{
			Name: name,
			Addr: addr,
		})
	}

	syms := ksyms.syms
	sort.Slice(syms, func(i, j int) bool {
		if syms[i].Addr == syms[j].Addr {
			return syms[i].Name >= syms[j].Name
		}
		return syms[i].Addr >= syms[j].Addr
	})

	ksyms.syms = syms
	return ksyms, nil
}

func (k *Ksyms) MapAddr(addr uint64) *Ksym {
	syms := k.syms
	i := sort.Search(len(syms), func(i int) bool {
		return syms[i].Addr <= addr
	})

	if i < len(syms) {
		v := syms[i]
		return &v
	}
	return nil
}

func (k *Ksyms) GetSymbol(name string) *Ksym {
	for _, v := range k.syms {
		v := v
		if v.Name == name {
			return &v
		}
	}
	return nil
}

type LoadRange struct {
	start   uint64
	end     uint64
	fileOff uint64
}

const (
	EXEC = iota
	DYN
	PERF_MAP
	VDSO
	UNKNOWN
)

type Sym struct {
	Name  string
	start uint
	size  uint
}

type Syms struct {
	dsos []Dso
}

func (s *Syms) MapAddr(addr uint64) *Sym {
	d, _ := s.findDso(addr)
	if d == nil {
		return nil
	}
	return nil
}

func (s *Syms) findDso(addr uint64) (*Dso, uint64) {
	var offset uint64
	for _, d := range s.dsos {
		for _, r := range d.ranges {
			if addr <= r.start || addr >= r.end {
				continue
			}
			if d._type == DYN || d._type == VDSO {
				/* Offset within the mmap */
				offset = addr - r.start + r.fileOff
				/* Offset within the ELF for dyn symbol lookup */
				offset += d.shAddr - d.shOffset
			} else {
				offset = addr
			}
			return &d, offset
		}
	}

	return nil, 0
}

func (s *Syms) find_sym() {

}

type Dso struct {
	name   string
	ranges []LoadRange
	// range_sz int
	/* Dyn's first text section virtual addr at execution */
	shAddr uint64
	/* Dyn's first text section file offset */
	shOffset uint64
	_type    int
	syms     []Sym

	/*
	 * libbpf's struct btf is actually a pretty efficient
	 * "set of strings" data structure, so we create an
	 * empty one and use it to store symbol names.
	 */
	// struct btf *btf;
}

func (d *Dso) findSym(offset uint64) *Sym {
	syms := d.syms
	i := sort.Search(len(syms), func(i int) bool {
		// return syms[i].Addr <= addr
		return true
	})

	if i < len(syms) {
		v := syms[i]
		return &v
	}
	return nil
}

func (d *Dso) loadSymTable() error {
	switch d._type {
	case PERF_MAP:
		return d.loadSymTableFromPerfMap()
	case EXEC, DYN:
		return d.loadSymTableFromElf(0)
	case VDSO:
		return d.loadSymTableFromVdsoImage()
	default:
		return errors.New("unsupported type")
	}
}

func (d *Dso) loadSymTableFromPerfMap() error {
	return errors.New("unsupported type")
}

func (d *Dso) loadSymTableFromElf(fd int) error {
	return nil
}

func (d *Dso) loadSymTableFromVdsoImage() error {
	return nil
}

type SymsCache struct {
	data []SymsCacheData
	// Nr   int
}

type SymsCacheData struct {
	syms Syms
	tgid int
}

func NewSymsCache() *SymsCache {
	return &SymsCache{}
}

func (s *SymsCache) GetSyms(tgid int) (*Syms, error) {
	for _, d := range s.data {
		if d.tgid == tgid {
			return &d.syms, nil
		}
	}

	syms, err := symsLoadPid(tgid)
	if err != nil {
		return nil, err
	}
	s.data = append(s.data, SymsCacheData{
		syms: *syms,
		tgid: tgid,
	})
	return syms, nil
}

func (s *Syms) addDso(m addrMap, name string) error {
	var d *Dso
	for _, item := range s.dsos {
		if item.name == name {
			d = &item
		}
	}
	if d == nil {
		d = &Dso{
			name: name,
		}
	}
	d.ranges = append(d.ranges, LoadRange{
		start:   m.startAddr,
		end:     m.endAddr,
		fileOff: m.fileOff,
	})

	elfType, err := getElfType(name)
	if err != nil {
		return err
	}
	if elfType == elf.ET_EXEC {
		d._type = EXEC
	} else if elfType == elf.ET_DYN {
		d._type = DYN
		var err error
		d.shAddr, d.shOffset, err = getElfTextScnInfo(name)
		if err != nil {
			return err
		}
	} else if isPerfMap(name) {
		d._type = PERF_MAP
	} else if isVdso(name) {
		d._type = VDSO
	} else {
		d._type = UNKNOWN
	}

	return nil
}

func getElfTextScnInfo(path string) (uint64, uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	for _, s := range f.Sections {
		if s.Name == ".text" {
			return s.Addr, s.Offset, nil
		}
	}
	return 0, 0, errors.New("not found")
}

func getElfType(path string) (elf.Type, error) {
	if isVdso(path) {
		return 0, nil
	}
	f, err := elf.Open(path)
	if err != nil {
		return 0, err
	}
	f.Close()
	return f.Type, nil
}

func symsLoadPid(tgid int) (*Syms, error) {
	name := fmt.Sprintf("/proc/%d/maps", tgid)
	return symsLoadFile(name)
}

type addrMap struct {
	startAddr uint64
	endAddr   uint64
	fileOff   uint64
	devMajor  uint64
	devMinor  uint64
	inode     uint64
}

func symsLoadFile(name string) (*Syms, error) {
	fdata, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var syms *Syms
	s := bufio.NewScanner(bytes.NewReader(fdata))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var addrMap addrMap
		var perm string
		var name string
		n, err := fmt.Fscanf(strings.NewReader(line),
			"%x-%x %4s %x %x:%x %u%s",
			&addrMap.startAddr, &addrMap.endAddr, &perm, &addrMap.fileOff,
			&addrMap.devMajor, &addrMap.devMinor, &addrMap.inode, &name)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		if len(perm) < 3 || perm[2] != 'x' {
			continue
		}
		if !isFileBacked(name) {
			continue
		}
		if isVdso(name) {
			break
		}
		if err := syms.addDso(addrMap, name); err != nil {
			return nil, err
		}
	}

	return syms, nil
}

func isFileBacked(mapname string) bool {
	if mapname == "" {
		return false
	}
	if strings.HasPrefix(mapname, "//anon") ||
		strings.HasPrefix(mapname, "/dev/zero") ||
		strings.HasPrefix(mapname, "/anon_hugepage") ||
		strings.HasPrefix(mapname, "[stack") ||
		strings.HasPrefix(mapname, "/SYSV") ||
		strings.HasPrefix(mapname, "[heap]") ||
		strings.HasPrefix(mapname, "[vsyscall]") {
		return false
	}
	return true
}

func isVdso(path string) bool {
	return path == "[vdso]"
}

func isPerfMap(path string) bool {
	return false
}
