#include <stdio.h>

// gcc -fPIC -shared -o libpic-hello.so pic-hello.c

__attribute__((visibility("default"))) int hello() {
  printf("Hook.zig has been injected!");
    return 1337;
}
