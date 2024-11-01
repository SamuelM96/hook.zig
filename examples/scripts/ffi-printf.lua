local ffi = require("ffi")

ffi.cdef([[
int printf(const char *fmt, ...);
]])

print(string.format("printf() @ 0x%x", ffi.cast("uintptr_t", ffi.C.printf)))
ffi.C.printf("Hello %s!\n", "FFI")
