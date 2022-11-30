module github.com/mozillazg/libbpfgo-tools/tools/fsdist

go 1.18

require (
	github.com/aquasecurity/libbpfgo v0.4.4-libbpf-1.0.1
	github.com/mozillazg/libbpfgo-tools/common v0.0.0
	github.com/spf13/pflag v1.0.5
)

replace github.com/aquasecurity/libbpfgo v0.4.4-libbpf-1.0.1 => github.com/mozillazg/libbpfgo v0.0.0-20221130135211-69775bc205a8

replace github.com/mozillazg/libbpfgo-tools/common v0.0.0 => ../../common
