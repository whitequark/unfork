#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <elf.h>

const size_t PAGE_SIZE = (size_t)sysconf(_SC_PAGESIZE);

// Allocation helpers.
extern int _end;

// Don't use libc malloc because it uses mmap but does not let us choose where the mapping
// will be placed, and we deal with enough unpredictability in our address space as is.
// Because of how static linking with musl works, this actually replaces the allocator of
// the libc itself as well, letting us use fopen() and friends.
alignas(alignof(max_align_t)) char heap[0x40000], *heap_end = &heap[0];

void *malloc(size_t size) {
  void *block = heap_end;
  size = (size + alignof(max_align_t) - 1) & ~(alignof(max_align_t) - 1);
  if ((ssize_t)size > &heap[sizeof(heap)] - heap_end) {
    errno = ENOMEM;
    return NULL;
  }
  heap_end += size;
  return block;
}

void free(void *) {}

void *realloc(void *block, size_t size) {
  void *new_block = malloc(size);
  if (new_block == NULL) return NULL;
  if (block != NULL) memcpy(new_block, block, size); // dirty but sound
  return new_block;
}

void *operator new(size_t size) {
  void *block = malloc(size);
  if (block == NULL) {
    fprintf(stderr, "out of memory in static heap (%zd bytes requested)\n", size);
    abort();
  }
  return block;
}

// Logging helpers.
void log(const char *format, ...) __attribute__((format (printf, 1, 2)));
void die(const char *format, ...) __attribute__((format (printf, 1, 2), noreturn));

void log(const char *format, ...) {
  va_list va;
  va_start(va, format);
  vfprintf(stderr, format, va);
  va_end(va);
}

void die(const char *format, ...) {
  va_list va;
  va_start(va, format);
  vfprintf(stderr, format, va);
  va_end(va);
  _exit(1);
}

#if UINTPTR_MAX > 0xffffffff
#define WPRIxPTR "%016" PRIxPTR
#define WPRIxSZ  "%016zx"
#else
#define WPRIxPTR "%08" PRIxPTR
#define WPRIxSZ  "%08zx"
#endif

// Unforking helpers.
pid_t pid = -1;

struct mapping {
  uintptr_t start, end;
  int prot;
  size_t offset;
  const char *pathname;
  struct mapping *prev, *next;
} *mappings = NULL, *rmappings = NULL;

struct shlib {
  const char *pathname;
  uintptr_t base;
  struct shlib *next;
} *shlibs = NULL;

int uffd = -1;

void *uffd_thread_fn(void *) {
  uint8_t cache[PAGE_SIZE];

  while (1) {
    struct uffd_msg uffd_msg;
    if (read(uffd, &uffd_msg, sizeof(uffd_msg)) == -1)
      die("[!] cannot read userfaultfd message: %s\n", strerror(errno));

    switch (uffd_msg.event) {
      case UFFD_EVENT_PAGEFAULT: {
        uintptr_t fault_addr = uffd_msg.arg.pagefault.address;
        log("[-] page fault at " WPRIxPTR " (%c)\n",
          fault_addr,
          (uffd_msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) ? 'w' : 'r');

        struct mapping *mapping_it;
        for (mapping_it = mappings; mapping_it; mapping_it = mapping_it->next) {
          if (mapping_it->start <= fault_addr && fault_addr < mapping_it->end) {
            break;
          } else if (mapping_it->end <= fault_addr) {
            mapping_it = NULL; // no chance now
            break;
          }
        }
        if (mapping_it == NULL)
          die("[!] address is not mapped\n");

        struct iovec local_iov[1] = { {cache, PAGE_SIZE} };
        struct iovec remote_iov[1] = { {(void*)fault_addr, PAGE_SIZE} };
        ssize_t read_bytes = process_vm_readv(pid,
          local_iov, sizeof(local_iov) / sizeof(local_iov[0]),
          remote_iov, sizeof(remote_iov) / sizeof(remote_iov[0]), 0);
        if (read_bytes != (ssize_t)PAGE_SIZE)
          die("[!] cannot transfer page to cache (%zd bytes done): %s\n",
            read_bytes, strerror(errno));

        struct uffdio_copy uffd_copy = {};
        uffd_copy.dst = fault_addr;
        uffd_copy.src = (uintptr_t)cache;
        uffd_copy.len = PAGE_SIZE;
        if (ioctl(uffd, UFFDIO_COPY, &uffd_copy) == -1)
          die("[!] cannot transfer page from cache (%zd bytes done): %s\n",
            (ssize_t)uffd_copy.copy, strerror(errno));

        break;
      }

      default:
        die("[!] unknown userfaultfd event %d\n", uffd_msg.event);
    }
  }
}

void unfork_process(int (*cont)()) __attribute__((noreturn));

struct unfork_stage2_info {
  int (*cont)();
  void *uffd_stack;
  size_t uffd_stack_size;
};

int unfork_stage2(void *);

// Map the same ranges as our target process, and use userfaultfd plus process_vm_readv to lazily
// populate them on access, with the same protection as well. This is essentially the inverse of
// fork: instead of ejecting pages to a new process with CoW, we inject pages into our own process
// with CoW.
//
// If any range overlaps with our code, mmap will silently overwrite it, and very bad things will
// likely happen. Because of that, this method works in one of two cases:
//   * this binary running on a 64-bit system and it has ASLR enabled (which makes collisions not
//     impossible, but comfortably unlikely), or
//   * this binary is small and statically linked to an address unlikely to be used by anything
//     it's likely to attempt to load, and takes care to relocate its dynamic mappings away.
void unfork_process(int (*cont)()) {
  char maps_filename[32] = {};
  snprintf(maps_filename, sizeof(maps_filename), "/proc/%d/maps", pid);
  FILE *maps = fopen(maps_filename, "r");
  if (!maps)
    die("[!] cannot open '%s'\n", maps_filename);

  // 557a17c2f000-557a17c31000 r--p 00000000 fd:01 6029777                    /bin/cat
  size_t line = 0;
  while (1) {
    uintptr_t start, end;
    char perms[4];
    size_t offset;
    uint8_t major, minor;
    uintmax_t inode;
    char *pathname = NULL;
    errno = 0;
    int parsed = fscanf(maps, "%" SCNxPTR "-%" SCNxPTR " %4c %zx %hhx:%hhx %jx%*[ ]%m[^\n]\n",
      &start, &end, perms, &offset, &major, &minor, &inode, &pathname);
    if (errno != 0)
      die("[!] cannot read maps: %s\n", strerror(errno));
    if (parsed == EOF)
      break;
    else if (!(parsed >= 7 && parsed <= 8))
      die("[!] cannot parse maps: %d fields recognized on line %zd\n", parsed, line);
    line++;

    int prot = 0;
    if (perms[0] == 'r') prot |= PROT_READ;
    if (perms[1] == 'w') prot |= PROT_WRITE;
    if (perms[2] == 'x') prot |= PROT_EXEC;
    mappings = new mapping { start, end, prot, offset, pathname, NULL, mappings };
    if (mappings->next == NULL)
      rmappings = mappings;
    else
      mappings->next->prev = mappings;

    if (pathname) {
      struct shlib *shlib_it;
      for (shlib_it = shlibs; shlib_it; shlib_it = shlib_it->next) {
        if (!strcmp(shlib_it->pathname, pathname)) break;
      }
      if (shlib_it == NULL)
        shlibs = new shlib { pathname, start, shlibs };
    }
  }

  fclose(maps);

  // We need a new stack for both the main thread and userfaultfd thread, since both of those
  // must be moved out of harm's way from their default allocations. By explicitly placing both
  // of these stacks, we also cause most libcs to place their TCBs and static TLS in the area
  // we specify, assuming the size of the static TLS block isn't too huge.
  const size_t stack_size = PAGE_SIZE * 16;
  uintptr_t hole_bottom = (((uintptr_t)&_end) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
  uintptr_t hole_top = 0;
  struct mapping *mapping_it;
  for (mapping_it = rmappings; mapping_it; mapping_it = mapping_it->prev) {
    if (mapping_it->start >= hole_bottom + 2 * stack_size) {
      hole_top = mapping_it->start;
      break;
    } else {
      hole_bottom = mapping_it->end;
    }
  }
  if (hole_bottom >= hole_top)
    die("[!] could not find a hole for stacks\n");
  log("[=] found hole for stacks at " WPRIxPTR "-" WPRIxPTR "\n",
    hole_bottom, hole_top);

  uintptr_t new_stack_bottom = hole_bottom;
  uintptr_t uffd_stack_bottom = new_stack_bottom + stack_size;

  void *new_stack = mmap((void *)new_stack_bottom, stack_size, PROT_READ|PROT_WRITE,
    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_STACK|MAP_GROWSDOWN, -1, 0);
  if (new_stack == MAP_FAILED)
    die("[!] cannot map new stack: %s\n", strerror(errno));
  log("[=] mapped new stack at " WPRIxPTR "-" WPRIxPTR "\n",
    (uintptr_t)new_stack, (uintptr_t)new_stack + stack_size);

  void *uffd_stack = mmap((void *)uffd_stack_bottom, stack_size, PROT_READ|PROT_WRITE,
    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_STACK|MAP_GROWSDOWN, -1, 0);
  if (uffd_stack == MAP_FAILED)
    die("[!] cannot map userfaultfd stack: %s\n", strerror(errno));
  log("[=] mapped userfaultfd stack at " WPRIxPTR "-" WPRIxPTR "\n",
    (uintptr_t)uffd_stack, (uintptr_t)uffd_stack + stack_size);

  unfork_stage2_info info = { cont, uffd_stack, stack_size };
  int child_tid = clone(unfork_stage2, (void*)((uintptr_t)new_stack + stack_size),
    SIGCHLD, (void *)&info, NULL);
  if (child_tid == -1)
    die("[!] cannot switch over to new stack: %s\n", strerror(errno));

  // For some reason clone breaks the link between the controlling terminal and the child thread,
  // which is quite annoying. Using pthread_create() and pthread_exit() in the main thread is even
  // worse; the process is shown as a zombie, and the child thread doesn't appear *anywhere*! Not
  // in ps, not in top, and any resources it consumes will be impossible to attribute. Quite weird,
  // given that the manpage actually recommends doing pthread_exit() in the main thread.
  int status;
  if (waitpid(child_tid, &status, 0) == -1)
    die("[!] cannot wait on stage2 thread: %s\n", strerror(errno));
  // Because of the above mentioned brokenness, try to pretend that clone() never happened in
  // the first place. This seems to result in the expected behavior in a shell.
  if (WIFEXITED(status))
    exit(status);
  else if (WIFSIGNALED(status))
    kill(getpid(), WTERMSIG(status));
  abort();
}

int unfork_stage2(void *info_p) {
  unfork_stage2_info info = *(unfork_stage2_info *)info_p;

  const char *maps_filename = "/proc/self/maps";
  FILE *maps = fopen(maps_filename, "r");
  if (!maps)
    die("[!] cannot open '%s'\n", maps_filename);

  log("[-] local mappings\n");
  while (1) {
    char line[1024];
    if (!fgets(line, sizeof(line), maps))
      break;
    fprintf(stderr, "[-]   %s", line);
  }

  fclose(maps);

  uffd = syscall(SYS_userfaultfd, 0);
  if (uffd == -1)
    die("[!] cannot create userfaultfd: %s\n", strerror(errno));

  struct uffdio_api uffd_api = {UFFD_API, 0, 0};
  if (ioctl(uffd, UFFDIO_API, &uffd_api) == -1)
    die("[!] cannot handshake on userfaultfd: %s\n", strerror(errno));

  if (!(uffd_api.ioctls & (1 << _UFFDIO_REGISTER)))
    die("[!] userfaultfd does not support required features\n");

  log("[=] remote mappings\n");
  struct mapping *mapping_it;
  uintptr_t vdso_addr = 0;
  for (mapping_it = rmappings; mapping_it; mapping_it = mapping_it->prev) {
    log("[=]   " WPRIxPTR "-" WPRIxPTR " %c%c%c  " WPRIxSZ " %s\n",
      mapping_it->start, mapping_it->end,
      (mapping_it->prot & PROT_READ)  ? 'r' : '-',
      (mapping_it->prot & PROT_WRITE) ? 'w' : '-',
      (mapping_it->prot & PROT_EXEC)  ? 'x' : '-',
      mapping_it->offset, mapping_it->pathname);

    // Check against now-highest used point in our address space, which is the top of userfaultfd
    // thread stack.
    if (mapping_it->start < (uintptr_t)info.uffd_stack + info.uffd_stack_size)
      die("[!] mapping interferes with agent code\n");

    void *mm = mmap((void *)mapping_it->start, mapping_it->end - mapping_it->start,
      mapping_it->prot, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (mm == MAP_FAILED)
      die("[!] cannot add mapping: %s\n", strerror(errno));

    struct uffdio_register uffd_register = {};
    uffd_register.range = {mapping_it->start, mapping_it->end - mapping_it->start};
    uffd_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffd_register) == -1)
      die("[!] cannot register mapping with userfaultfd: %s\n", strerror(errno));

    if (!(uffd_register.ioctls & (1 << _UFFDIO_COPY)))
      die("[!] userfaultfd mapping does not support required features\n");

    if (mapping_it->pathname && !strcmp(mapping_it->pathname, "[vdso]"))
      vdso_addr = mapping_it->start;
  }

  pthread_t uffd_thread;
  pthread_attr_t attr;
  if (pthread_attr_init(&attr) != 0)
    die("[!] cannot init pthread attributes: %s\n", strerror(errno));
  if (pthread_attr_setstack(&attr, info.uffd_stack, info.uffd_stack_size) != 0)
    die("[!] cannot configure userfaultfd thread stack: %s\n", strerror(errno));
  if (pthread_create(&uffd_thread, &attr, uffd_thread_fn, NULL) != 0)
    die("[!] cannot create userfaultfd thread: %s\n", strerror(errno));
  if (pthread_attr_destroy(&attr) != 0)
    die("[!] cannot destroy pthread attributes: %s\n", strerror(errno));

#ifdef __i386
  // The Pentium II SYSENTER/SYSEXIT instruction pair is really cursed. In certain conditions,
  // SYSENTER does not save entry EFLAGS, EIP or ESP, which is why it may only occur inside vDSO;
  // Linux will issue SYSEXIT such that EIP after return to user mode always points inside vDSO,
  // or rather, where it thinks the vDSO is. That's right--the vDSO on i386 may not be moved.
  //
  // We have to move the vDSO around anyway (since it's affected by ASLR), so we work around this
  // by patching the vDSO to remove SYSENTER and fall back to INT $0x80, which is slower but
  // isn't totally braindead.
  Elf32_Ehdr *vdso_ehdr = (Elf32_Ehdr *)vdso_addr;
  uint8_t *vdso_entry = (uint8_t *)(vdso_addr + vdso_ehdr->e_entry);
  const size_t vdso_sig_size = 9;
  if (!memcmp(vdso_entry, "\x51\x52\x55\x89\xe5\x0f\x34\xcd\x80", vdso_sig_size)) {
    log("[=] patching vDSO to use INT $0x80 instead of SYSENTER\n");
    if (mprotect(vdso_entry, vdso_sig_size, PROT_READ|PROT_WRITE) != 0)
      die("[!] cannot remap vDSO as read/write\n");
    vdso_entry[5] = 0x90;
    vdso_entry[6] = 0x90;
    if (mprotect(vdso_entry, vdso_sig_size, PROT_READ|PROT_EXEC) != 0)
      die("[!] cannot remap vDSO as read/execute\n");
  } else if (!memcmp(vdso_entry, "\x51\x52\x55\x89\xe5\x90\x90\xcd\x80", vdso_sig_size)) {
    log("[=] vDSO already uses INT $0x80\n");
  } else {
    die("[!] unrecognized vDSO entry point signature\n");
  }
#else
  (void)vdso_addr;
#endif

  exit(info.cont());
}

#if UINTPTR_MAX > 0xffffffff
#define ElfW(type) Elf64_ ## type
#define ELFCLASSW ELFCLASS64
#else
#define ElfW(type) Elf32_ ## type
#define ELFCLASSW ELFCLASS32
#endif

uintptr_t get_symbol(const char *shlib_name, const char *sym_name,
                     size_t *sym_size = NULL) {
  log("[=] looking for symbol '%s' in shared library '%s'\n", sym_name, shlib_name);

  struct shlib *shlib_it;
  for (shlib_it = shlibs; shlib_it; shlib_it = shlib_it->next) {
    if (strlen(shlib_it->pathname) >= strlen(shlib_name) &&
        !strcmp(shlib_it->pathname + strlen(shlib_it->pathname) - strlen(shlib_name), shlib_name))
      break;
  }
  if (shlib_it == 0)
    die("[!] library not mapped\n");
  uintptr_t base = shlib_it->base;

  const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr) *)base;
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
    die("[!] invalid ELF header\n");
  if (ehdr->e_ident[EI_CLASS] != ELFCLASSW || ehdr->e_type != ET_DYN)
    die("[!] invalid ELF type\n");

  const ElfW(Phdr) *ph_dyn = NULL;
  for (size_t i = 0; i < ehdr->e_phnum; i++) {
    const ElfW(Phdr) *phdr = (const ElfW(Phdr) *)(base + ehdr->e_phoff + i * ehdr->e_phentsize);
    if (phdr->p_type == PT_DYNAMIC) {
      ph_dyn = phdr;
      break;
    }
  }
  if (ph_dyn == NULL)
    die("[!] PT_DYNAMIC not found\n");

  const ElfW(Dyn) *dyn = (const ElfW(Dyn) *)(base + ph_dyn->p_vaddr);
  const ElfW(Word) *hash = NULL;
  const char *strtab = NULL;
  const ElfW(Sym) *symtab = NULL;
  size_t syment = 0;
  for (; dyn->d_tag != DT_NULL; dyn++) {
    // Huh, ld.so relocates these in place.
    if (dyn->d_tag == DT_HASH)
      hash = (const ElfW(Word) *)dyn->d_un.d_ptr;
    if (dyn->d_tag == DT_STRTAB)
      strtab = (const char *)dyn->d_un.d_ptr;
    if (dyn->d_tag == DT_SYMTAB)
      symtab = (const ElfW(Sym) *)dyn->d_un.d_ptr;
    if (dyn->d_tag == DT_SYMENT)
      syment = dyn->d_un.d_val;
  }
  if (hash == NULL || strtab == NULL || symtab == NULL || syment == 0)
    die("[!] DT_HASH or DT_STRTAB or DT_SYMTAB or DT_SYMENT not found\n");

  for (size_t i = 0; i < hash[1]; i++) {
    const ElfW(Sym) *sym = (const ElfW(Sym) *)((uintptr_t) symtab + i * syment);
    if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC &&
        ELF32_ST_TYPE(sym->st_info) != STT_OBJECT) continue;
    if (!strcmp(sym_name, &strtab[sym->st_name])) {
      // But not the actual symbols, so we'll relocate those ourselves.
      uintptr_t sym_addr = base + sym->st_value;
      log("[=] symbol found at " WPRIxPTR " with size %0zx\n", sym_addr, sym->st_size);
      if (sym_size != NULL) *sym_size = sym->st_size;
      return sym_addr;
    }
  }

  die("[!] symbol not found\n");
}

// start pilfering from glibc
typedef union dtv
{
  size_t counter;
  struct {
    void *val;
    void *to_free;
  } pointer;
} dtv_t;

struct rtld_global {
  // If this shit breaks, `p (&_rtld_global._dl_tls_static_used-&_rtld_global)/sizeof(void*)` or
  // something like that works. Sorry, I ain't in the mood to track down like five hundred
  // dependencies of internal glibc headers.
#ifdef __x86_64
  void *_padding0[490];
#elif __i386
  void *_padding0[521];
#else
#error "Unsupported architecture"
#endif
  size_t _dl_tls_static_nelem;
  size_t _dl_tls_static_size;
  size_t _dl_tls_static_used;
  size_t _dl_tls_static_align;
  void *_dl_initial_dtv;
  void *_padding2[4];
};
// end pilfering from glibc

// Our unforking setup is quite good, but not perfect: we do not (yet) have the information to set
// up TLS. Lots of things rely on TLS (for example, errno and malloc), so it's important to get
// this right. Depending on the platform, TP could contain either TCB (x86 and x86_64 does this),
// or DTV (pretty much everything else). On x86(-64), we exploit the fact that (a) the first DTV
// is the DTV of the main executable, (b) with initial-exec TLS model the TLS static block
// immediately precedes the TCB, and (c) the DTV of the main executable points to the TLS static
// block. See https://chao-tic.github.io/blog/2018/12/25/tls for details. Unfortunately, there
// really isn't any other fully deterministic way to grab the address of initial TCB on x86(-64)
// using memory snapshots alone.
//
// For threads created with pthread_create(), the TCB is located at the bottom of the stack, and
// it always contains a pointer to DTV, although at an architecture-specific location, so those
// are much easier.
uintptr_t get_initial_tp() {
  struct shlib *shlib_it;
  for (shlib_it = shlibs; shlib_it; shlib_it = shlib_it->next) {
    if (strstr(shlib_it->pathname, "/ld-")) break;
  }
  if (shlib_it == NULL)
    die("[!] rtld not found\n");
  log("[=] found rtld %s\n", shlib_it->pathname);

  size_t sizeof__rtld_global;
  struct rtld_global *_rtld_global =
    (struct rtld_global *)get_symbol(shlib_it->pathname, "_rtld_global", &sizeof__rtld_global);
  if (sizeof__rtld_global != sizeof(struct rtld_global))
    die("[!] rtld_global size mismatch, expected %zx\n", sizeof(struct rtld_global));

  dtv_t *dtv = (dtv_t *)_rtld_global->_dl_initial_dtv;
  log("[=] found DTV at " WPRIxPTR "\n", (uintptr_t)dtv);

  uintptr_t tp;
#if defined(__i386) || defined(__x86_64)
  // _dl_tls_static_used is the aggregate size of all static TLS blocks, which can be more than
  // one in case the application loads a DSO with static TLS relocations. This adds restrictions
  // on loading order, but is nevertheless used for very hot __thread variables, the notable
  // example being the implicit context in libgl.
  //
  // I'm not 100% sure this calculation is correct (there's something funky going on with TCB
  // alignment), so we'll double check that the TCB address we got actually points to TCB.
  uintptr_t tcb = ((uintptr_t)dtv[_rtld_global->_dl_tls_static_nelem].pointer.val +
    _rtld_global->_dl_tls_static_used) & ~(_rtld_global->_dl_tls_static_align - 1);
  log("[=] guessed TCB at " WPRIxPTR "\n", (uintptr_t)dtv);
  tp = (uintptr_t)tcb;
  // On TCB-at-TP architectures, the first word of TCB points back at the TCB itself, so we can
  // use that to check that we indeed have the right TCB pointer. The second points to DTV.
  if (!((*(void **)tcb == (void *)tcb) || (*((void **)tcb + 1) == (void *)dtv)))
    die("[!] located initial TP at " WPRIxPTR " but sanity check failed\n", tp);
#else
#error "Unsupported architecture"
  // Usually just
  //    tp = (uintptr_t)dtv;
#endif
  log("[=] located initial TP at " WPRIxPTR "\n", tp);
  return tp;
}

#if defined(__x86_64)
#include <asm/prctl.h>

static inline long raw_syscall_2(long nr, long a1, long a2) {
  long ret;
  __asm__ __volatile__("syscall"
           : "=a"(ret)
           : "a"(nr), "D"(a1), "S"(a2)
           : "rcx", "r11", "memory");
  return ret;
}
#elif defined(__i386)
#include <asm/ldt.h>

static inline int raw_get_gs() {
  int gs;
  __asm__ __volatile__("movw %%gs, %w0" : "=r" (gs));
  return gs & 0xffff;
}

static inline void raw_set_gs(int gs) {
  __asm__ __volatile__("movw %w0, %%gs" :: "r" (gs));
}

static inline int raw_syscall_1(int nr, int a1) {
  int ret;
  __asm__ __volatile__("int $0x80"
           : "=a"(ret)
           : "a"(nr), "b"(a1)
           : "memory");
  return ret;
}

static inline int raw_get_thread_area(uintptr_t *tp, unsigned entry_number) {
  struct user_desc gs_desc = {};
  gs_desc.entry_number = entry_number;
  if (raw_syscall_1(SYS_get_thread_area, (int)&gs_desc) == 0) {
    *tp = gs_desc.base_addr;
    return 0;
  }
  return -1;
}

static inline int raw_set_thread_area(uintptr_t tp, unsigned entry_number = (unsigned)-1) {
  struct user_desc gs_desc = {
    .entry_number = entry_number,
    .base_addr = tp,
    .limit = 0xfffff,
    .seg_32bit = 1,
    .contents = 0,
    .read_exec_only = 0,
    .limit_in_pages = 1,
    .seg_not_present = 0,
    .useable = 1,
  };
  if (raw_syscall_1(SYS_set_thread_area, (int)&gs_desc) == 0)
    return gs_desc.entry_number * 8 + 3;
  return -1;
}
#endif

template<typename Fn, typename... Args>
auto call_with_tp(uintptr_t tp, Fn fn, Args&&... args) {
  log("[-] calling " WPRIxPTR "\n", (uintptr_t)fn);
#if defined(__x86_64)
  uintptr_t old_fsbase, new_fsbase = tp;
  if (syscall(SYS_arch_prctl, ARCH_GET_FS, &old_fsbase) != 0)
    die("[!] cannot get FSBASE: %s\n", strerror(errno));
  log("[-] local FSBASE " WPRIxPTR ", remote FSBASE " WPRIxPTR "\n", old_fsbase, new_fsbase);
  // syscall() uses TLS in several ways (errno, stack canary, etc), so avoid touching libc while
  // fsbase has the remote value. For the same reason we can't handle failure gracefully here.
  if (raw_syscall_2(SYS_arch_prctl, ARCH_SET_FS, new_fsbase) != 0)
    abort();
  auto ret = fn(args...);
  if (raw_syscall_2(SYS_arch_prctl, ARCH_SET_FS, old_fsbase) != 0)
    abort();
#elif defined(__i386)
  uintptr_t old_gsbase, new_gsbase = tp;
  int old_gs = raw_get_gs();
  // Same concerns as above.
  if (raw_get_thread_area(&old_gsbase, old_gs >> 3) == -1)
    die("[!] cannot get thread area: %s\n", strerror(errno));
  static int new_gs = -1;
  new_gs = raw_set_thread_area(new_gsbase, new_gs >> 3);
  if (new_gs == -1)
    die("[!] cannot set thread area: %s\n", strerror(errno));
  log("[-] local GS %04x GSBASE " WPRIxPTR " remote GS %04x GSBASE " WPRIxPTR "\n",
    old_gs, old_gsbase, new_gs, new_gsbase);
  raw_set_gs(new_gs);
  auto ret = fn(args...);
  raw_set_gs(old_gs);
#else
#error "Unsupported architecture"
#endif
  return ret;
}

int main2();

int main(int argc, char **argv) {
  if (argc != 2)
    die("usage: %s $(pidof <process>)\n", argv[0]);

  char *s_pid = argv[1], *s_pidend;
  pid = strtol(s_pid, &s_pidend, 10);
  if (*s_pidend)
    die("[!] pid is not a number\n");

  unfork_process(main2);
}

int main2() {
  uintptr_t initial_tp = get_initial_tp();

  struct shlib *shlib_it;
  for (shlib_it = shlibs; shlib_it; shlib_it = shlib_it->next) {
    if (strstr(shlib_it->pathname, "/libc-")) break;
  }
  if (shlib_it == NULL)
    die("[!] libc not found\n");
  log("[=] found libc %s\n", shlib_it->pathname);
  const char *libc_pathname = shlib_it->pathname;

  int (*xputs)(const char *) = (int (*)(const char *))get_symbol(libc_pathname, "puts");
  call_with_tp(initial_tp, xputs, "hello, world");
  call_with_tp(initial_tp, xputs, "hello, again");

  // If the above calls don't appear to print anything, it might be that stdout is in block-
  // and not line-buffered mode, so let's flush it. The weird _IO_2_1_ fuckery is related to
  // glibc ABI compatibility. We already require the target to use glibc (since we poke ld.so
  // internals directly, and glibc's ld.so doesn't work with any other libc.so), so it's safe
  // to depend on it here as well.
  int (*xfflush)(FILE *) = (int (*)(FILE *))get_symbol(libc_pathname, "fflush");
  FILE *xstdout = (FILE *)get_symbol(libc_pathname, "_IO_2_1_stdout_");
  call_with_tp(initial_tp, xfflush, xstdout);

  return 0;
}
