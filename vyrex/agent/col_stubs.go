package main

// The eBPF and YARA stage-in stubs that lived here have been replaced by real, buildable,
// dependency-free collectors:
//
//   eBPF  -> col_procmon.go : poll-based /proc process-start observation (Linux runtime).
//   YARA  -> col_yara.go    : pure-Go literal/hex IOC file scanning.
//
// Both honestly document the gap to their full production forms (kernel-level cilium/ebpf and
// libyara via cgo) in their own files. This file is intentionally left as a marker so the
// history of the extension points stays clear.
