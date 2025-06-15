// tls_probe.c - 主入口文件，包含所有TLS挂载点模块
// 这个文件现在作为所有拆分模块的统一入口点

// 包含公共头文件和定义
#include "common.h"
#include "maps.h"
#include "helpers.c"

// 包含各个TLS库的探针实现
#include "openssl_probe.c"
#include "boringssl_probe.c"
#include "gnutls_probe.c"
#include "gotls_probe.c"
#include "syscall_probe.c"
#include "kernel_probe.c"
#include "kernel_probe_connect.c"

char LICENSE[] SEC("license") = "GPL";