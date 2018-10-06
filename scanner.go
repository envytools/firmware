// Copyright (c) 2018 Ilia Mirkin.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// To run directly from source:
// $ go run scanner.go path/to/nv-kernel.o_binary output-dir
//
// To make a reusable binary:
// $ go build scanner.go
// $ ./scanner path/to/nv-kernel.o_binary output-dir
//
// Tested on 387.34 and 390.48 blobs. Should work on a wider range.
//
// Premise is to parse the relocations table to look for offests into
// rodata, where the firmware is stored. We assume that rodata is
// reasonably well-packed, and try to process the data in between
// relocations.
//
// The assumption is that the data is deflated (but without
// headers). This applies both to the netlist archives, as well as the
// video/pmu/etc firmware which is stored "raw".

package main

import "bytes"
import "compress/flate"
import "debug/elf"
import "encoding/binary"
import "fmt"
import "io/ioutil"
import "os"
import "path"
import "sort"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// from https://nv-tegra.nvidia.com/gitweb/?p=linux-nvgpu.git;a=blob;f=drivers/gpu/nvgpu/gk20a/gr_ctx_gk20a.h;hb=refs/tags/tegra-l4t-r31.0.2#l73
var names = map[int]string{
	0: "fecs_data",
	1: "fecs_inst",
	2: "gpccs_data",
	3: "gpccs_inst",
	4: "sw_bundle_init",
	5: "sw_ctx",
	6: "sw_nonctx",
	7: "sw_method_init",
	8: "ctxreg_sys",
	9: "ctxreg_gpc",
	10: "ctxreg_tpc",
	11: "ctxreg_zcull_gpc",
	12: "ctxreg_pm_sys",
	13: "ctxreg_pm_gpc",
	14: "ctxreg_pm_tpc",
	15: "majorv",
	16: "buffer_size",
	17: "ctxsw_reg_base_index",
	18: "netlist_num",
	19: "ctxreg_ppc",
	20: "ctxreg_pmppc",
	21: "nvperf_ctxreg_sys",
	22: "nvperf_fbp_ctxregs",
	23: "nvperf_ctxreg_gpc",
	24: "nvperf_fbp_router",
	25: "nvperf_gpc_router",
	26: "ctxreg_pmltc",
	27: "ctxreg_pmfbpa",
	28: "swveidbundleinit",
	29: "nvperf_sys_router",
	30: "nvperf_pma",
	31: "ctxreg_pmrop",
	32: "ctxreg_pmucgpc",
	33: "ctxreg_etpc",
	34: "sw_bundle64_init",
	35: "nvperf_pmcau",
}

type Processor struct {
	Destdir string
	archiveCounter, wholeCounter int
}
type ArchiveHeader struct {
	Magic, Count int32
}
type ArchiveEntry struct {
	Id, Length, Offset int32
}

func (p *Processor) Process(data []byte) {

	// If the data starts with the "magic" zero value (and is
	// large enough and has few enough entries to make sense),
	// assume it's an archive, and try to parse it that way.
	var header ArchiveHeader
	dataReader := bytes.NewReader(data)
	err := binary.Read(dataReader, binary.LittleEndian, &header)
	if len(data) < 32768 || header.Magic != 0 || header.Count > 64 {
		// A lot of small seemingly compressed files that
		// don't appear to mean much. Since there is no
		// compression header, there's a lot of potential for
		// garbage.
		if len(data) < 128 {
			return
		}

		// Dump out the file and continue
		fname := path.Join(p.Destdir,
			fmt.Sprintf("whole_%03d", p.wholeCounter))
		err = ioutil.WriteFile(fname, data, os.FileMode(0666))
		must(err)

		p.wholeCounter++
		return
	}

	// Parse all the entries. Bail if any of them don't make
	// sense, e.g. have offsets that are in the entry descriptions
	// section.
	entries := make([]ArchiveEntry, header.Count)
	minOffset := int32(8 + 12 * len(entries))
	for i, _ := range entries {
		err = binary.Read(dataReader, binary.LittleEndian, &entries[i])
		if err != nil || entries[i].Offset < minOffset {
			return
		}
	}
	if len(entries) == 0 {
		return
	}

	// Create a directory for the archive, and put each entry into
	// its own file. Use the known names when possible.
	archbase := path.Join(p.Destdir,
		fmt.Sprintf("archive_%02d", p.archiveCounter))
	os.Mkdir(archbase, os.FileMode(0777))
	for _, entry := range entries {
		name := names[int(entry.Id)]
		if name == "" {
			name = fmt.Sprintf("unk%d", entry.Id)
		}
		fname := path.Join(archbase, name)
		err = ioutil.WriteFile(fname,
			data[entry.Offset:entry.Offset+entry.Length],
			os.FileMode(0666))
		must(err)
	}
	p.archiveCounter++
}

func ParseRelocations(f *elf.File, relSection, section string) (offsets []int64) {
	relsS := f.Section(relSection)
	rels, err := relsS.Data()
	must(err)
	if len(rels) % 24 != 0 {
		panic(fmt.Errorf("Unexpected length for %s: %x\n",
			relSection, len(rels)))
	}

	symbols, err := f.Symbols()
	must(err)

	// Borrowed from the debug/elf relocation processing logic
	b := bytes.NewReader(rels)
  	var rela elf.Rela64
	for b.Len() > 0 {
		err = binary.Read(b, f.ByteOrder, &rela)
		must(err)

		symNo := rela.Info >> 32
		sym := &symbols[symNo-1]
		if elf.SymType(sym.Info & 0xf) != elf.STT_SECTION ||
			f.Sections[sym.Section].Name != section {
			// We're only looking for relocations into the
			// target section
			continue
		}

		offsets = append(offsets, rela.Addend)
	}
	return
}

func main() {
	kernel_f := os.Args[1]
	f, err := elf.Open(kernel_f)
	must(err)

	destdir := os.Args[2]

	// The data actually resides in rodata
	rodataS := f.Section(".rodata")
	rodata, err := rodataS.Data()
	must(err)

	// The relocations for rodata tell us where potentially
	// interesting data might start.
	//
	// TODO: Should we parse other sections for rodata relocations?
	offsets := ParseRelocations(f, ".rela.rodata", ".rodata")
	offsets = append(offsets, int64(len(rodata)))

	sort.Slice(offsets, func (a, b int) bool {
		return offsets[a] < offsets[b]
	})

	// We assume these offsets are tightly packed in rodata. So
	// look at sequential entries in the sorted list of offsets.
	p := &Processor{Destdir: destdir}
	for i, off := range offsets {
		var prev int64
		if i > 0 {
			prev = offsets[i - 1]
		}
		// Check that there's enough data between sequential offsets
		if off - prev < 32 {
			continue
		}

		// Attempt to decompress using basic flate algorithm
		// (underlying deflate/gzip)
		rodataReader := bytes.NewReader(rodata[prev:off])
		c := flate.NewReader(rodataReader)
		data, err := ioutil.ReadAll(c)
		if err != nil {
			continue
		}

		p.Process(data)
	}
}
