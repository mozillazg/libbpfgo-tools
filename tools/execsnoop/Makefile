
TOOL_NAME = $(shell basename $(abspath ./))
LIBBPF_TOOLS = ../../bcc/libbpf-tools

LIBBPF_TOOLS_OUTPUT = $(abspath $(LIBBPF_TOOLS)/.output)
LIBBPF_OBJ = $(abspath $(LIBBPF_TOOLS_OUTPUT)/libbpf.a)
TOOL_BPF_OBJ = $(abspath $(LIBBPF_TOOLS_OUTPUT)/$(TOOL_NAME).bpf.o)

CLANG = clang

CGO_CFLAGS_STATIC = "-I$(abspath $(LIBBPF_TOOLS_OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

.PHONY: $(TOOL_NAME)
$(TOOL_NAME): $(TOOL_NAME).bpf.o
	CC=$(CLANG) CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	go build -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC)

.PHONY: $(TOOL_NAME).bpf.o
$(TOOL_NAME).bpf.o:
	cp $(TOOL_BPF_OBJ) ./
