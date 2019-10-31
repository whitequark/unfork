#ifndef UNFORK_H
#define UNFORK_H

#include <inttypes.h>
#include <stdint.h>
#include <stddef.h>

uintptr_t get_symbol(const char *shlib_pat, const char *sym_name, size_t *sym_size = NULL);

uintptr_t get_initial_tp();
void *call_with_tp_raw(uintptr_t tp, void *(*fn)(void *), void *arg);

template<class Fn>
void call_with_tp(uintptr_t tp, Fn fn) {
  call_with_tp_raw(tp, [](void *arg) {
    decltype(fn) *fn2 = (decltype(fn) *)arg;
    (*fn2)();
    return (void *)NULL;
  }, (void *)&fn);
}

#endif
