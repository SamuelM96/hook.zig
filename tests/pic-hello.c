#include <stdio.h>

// gcc -fPIC -shared -o libpic-hello.so pic-hello.c

__attribute__((visibility("default"))) void hello() {
  printf("Hook.zig has been injected!");
}
