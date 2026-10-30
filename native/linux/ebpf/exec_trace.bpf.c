// LEGACY - DO NOT USE AS behavedr_exec.bpf.o
//
// This file is retained only as historical reference. It uses BPF_MAP_TYPE_RINGBUF
// and a different event layout than LinuxEbpfLoader expects (array map + cursor +
// 144-byte suite records from behavedr_suite.bpf.c).
//
// Production object:
//   clang ... -c behavedr_suite.bpf.c -o behavedr_exec.bpf.o
//
// build-native.sh will NOT fall back to this file (0.3.4+).

#error "exec_trace.bpf.c is legacy and incompatible with LinuxEbpfLoader. Build behavedr_suite.bpf.c instead."
