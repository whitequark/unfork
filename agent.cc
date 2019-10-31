#include <stdio.h>
#include "unfork.hh"

// Note that agent's stderr cannot be used at all here, since the userfaultfd handler might need
// it to print an error, and if a fault happens inside an stdio function--for example, if you call
// fprintf(stderr, "%s\n", remote_string)--deadlock will result.
int agent() {
  int (*xputs)(const char *) = (int (*)(const char *))get_symbol("libc*.so", "puts");
  int (*xfflush)(FILE *) = (int (*)(FILE *))get_symbol("libc*.so", "fflush");
  // The weird _IO_2_1_ fuckery is specific for glibc ABI; we already use ld.so internals directly,
  // so it's safe to assume it's present here.
  FILE *xstdout = (FILE *)get_symbol("libc*.so", "_IO_2_1_stdout_");

  call_with_tp(get_initial_tp(), [&] {
    xputs("hello, world");
    xputs("hello, again");
    // In case stdout somehow ended up in line buffered mode, flush it explicitly.
    xfflush(xstdout);
  });
  return 0;
}
