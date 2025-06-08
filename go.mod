module github.com/danl5/grpcapture

go 1.24.2

replace github.com/danl5/htrack => ../htrack

require (
	github.com/cilium/ebpf v0.18.0
	github.com/danl5/htrack v0.0.0-20250606134602-ee378657c67e
)

require (
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)
