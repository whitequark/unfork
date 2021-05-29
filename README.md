unfork(2)
=========

Introduction
------------

### Q: What the hell is this?

**A:** The inverse of fork(2).

### Q: That doesn't explain a lot.

**A:** Not really a question, but sure. fork(2) splits one process (really, address space) into two. unfork(2) joins two address spaces into one.

### Q: And doesn't sound very useful.

**A:** More of a comment again. Think of this technique as taking a cheap snapshot of another application that you can read, write, execute, discard, repeat, all while leaving no <sub>p</sub>*trace* and sending no *signal*. Heh.

### Q: How would that even work?

**A:** The magic of Linux! By combining [`userfaultfd`][] with [`process_vm_readv`][], any userspace application can obtain a copy-on-write mapping (with some limitations) of memory it never owned. All it needs is ptrace privileges, which is to say, having the same uid usually works.

[`userfaultfd`]: http://www.man7.org/linux/man-pages/man2/userfaultfd.2.html
[`process_vm_readv`]: http://man7.org/linux/man-pages/man2/process_vm_readv.2.html

### Q: Still, what do you actually need it for?

**A:** Dynamic binary analysis and instrumentation of applications with built-in integrity checks. As far as I know `process_vm_readv` isn't even detectable if the agent process is more privileged than the examinee process—so you're free to manipulate your private copy of the application in the comfort of your own address space.

### Q: How limited is this approach?

**A:** It's true that meshing address spaces is much harder than copying them. Especially on 32-bit systems, the likelihood of a collision is high, and that's why everything is built using [musl][], which excels at producing compact, straightforward binaries that fit into the areas the kernel doesn't place anything into; 64-bit systems with ASLR are far more forgiving. Nevertheless, I think that with some effort two allocators or even dynamic linkers could survive together.

In terms of functionality, you get virtual memory and [TLS](https://en.wikipedia.org/wiki/Thread-local_storage "Thread-Local Storage, not that socket thing") (TLS is everywhere!) but not, say, files or shared memory; at some point a kernel module would be necessary. On the platform support side, x86_64 and i386 seem to work well, and those two are also the most challenging ones.

[musl]: https://musl.libc.org/

### Q: Very interesting, thank you.

**A:** You're welcome!

Getting started
---------------

Keep in mind that this repository is nothing more than a proof of concept.

You'll need [patched](musl-no-vdso.patch) musl-gcc. (Using stock musl mostly works by accident on x86_64, but will usually crash on i386 without the patch.) After that, check the paths in the `*.specs` files, run `make` and it's done.

The demo code uses `puts` as an entry point and prints two messages; the first one using a clean snapshot of another process, and the second one reusing the same snapshot. Any process that dynamically loads `libc.so` works, e.g. `/bin/cat`. Run `./unfork[32|64].elf $(pidof cat)` and enjoy.

Although `puts` may seem trivial, it involves a surprisingly deep call stack (well... in glibc), syscalls, TLS, vDSOs, and is probably more complicated than the kind of problems I originally set out to solve.

License
-------

[0-clause BSD](LICENSE-0BSD.txt).
