#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  uint64_t i = 0;
  while (1) {
    printf("%lu\n", i);
    sleep(1);
    i += 1;
  }
  return 0;
}
