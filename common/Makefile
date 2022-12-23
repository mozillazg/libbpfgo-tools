
.ONESHELL:
SHELL = /bin/sh

BCC_SRC = ../../bcc
LIBBPF_SRC = $(BCC_SRC)/src/cc/libbpf
LIBBPF_TOOLS_SRC = $(BCC_SRC)/libbpf-tools
BPFTOOL_SRC = $(LIBBPF_TOOLS_SRC)/bpftool

LIBBPF_TOOLS_OUTPUT = $(abspath $(LIBBPF_TOOLS_SRC)/.output)
LIBBPF_OBJ = $(abspath $(LIBBPF_TOOLS_OUTPUT)/libbpf.a)

CLANG = clang
GIT = git

TOOL_NAME = $(shell basename $(abspath ./))
TOOL_BPF_OBJ = $(abspath $(LIBBPF_TOOLS_OUTPUT)/$(TOOL_NAME).bpf.o)

CGO_CFLAGS_STATIC = "-I$(abspath $(LIBBPF_TOOLS_OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

.PHONY: $(TOOL_NAME)
$(TOOL_NAME): $(TOOL_NAME).bpf.o
	CC=$(CLANG) CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	go build -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC)

.PHONY: $(TOOL_NAME).bpf.o
$(TOOL_NAME).bpf.o: $(LIBBPF_SRC) $(BPFTOOL_SRC) $(TOOL_BPF_OBJ)
	cp $(TOOL_BPF_OBJ) ./

.PHONY: $(LIBBPF_SRC)
$(LIBBPF_SRC):
	cd $(BCC_SRC)
	$(GIT) submodule update --init --recursive

.PHONY: $(BPFTOOL_SRC)
$(BPFTOOL_SRC):
	cd $(BCC_SRC)
	$(GIT) submodule update --init --recursive

.PHONY: $(TOOL_BPF_OBJ)
$(TOOL_BPF_OBJ):
	cd $(LIBBPF_TOOLS_SRC)
	$(MAKE)
