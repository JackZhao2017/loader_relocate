

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>



#include "loader_soinfo.h"
#include "printlog.h"

void soinfo::CallArray(const char* array_name __unused, linker_function_t* functions, size_t count, bool reverse) {
  if (functions == NULL) {
    return;
  }

  //TRACE("[ Calling %s (size %zd) @ %p for '%s' ]", array_name, count, functions, name);

  int begin = reverse ? (count - 1) : 0;
  int end = reverse ? -1 : count;
  int step = reverse ? -1 : 1;

  for (int i = begin; i != end; i += step) {
    //TRACE("[ %s[%d] == %p ]", array_name, i, functions[i]);
    CallFunction("function", functions[i]);
  }

  //TRACE("[ Done calling %s for '%s' ]", array_name, name);
}

void soinfo::CallFunction(const char* function_name __unused, linker_function_t function) {
  if (function == NULL || reinterpret_cast<uintptr_t>(function) == static_cast<uintptr_t>(-1)) {
    return;
  }

  info_msg("[ Calling %s @ %p  ]\n", function_name, function);
  function();
  info_msg("[ Done calling %s @ %p  ]\n", function_name, function);

  // The function may have called dlopen(3) or dlclose(3), so we need to ensure our data structures
  // are still writable. This happens with our debug malloc (see http://b/7941716).
  

  //protect_data(PROT_READ | PROT_WRITE);

}

void soinfo::CallPreInitConstructors() {
  // DT_PREINIT_ARRAY functions are called before any other constructors for executables,
  // but ignored in a shared library.
  CallArray("DT_PREINIT_ARRAY", preinit_array, preinit_array_count, false);
}

void soinfo::CallConstructors() {
  if (constructors_called) {
    return;
  }

  // We set constructors_called before actually calling the constructors, otherwise it doesn't
  // protect against recursive constructor calls. One simple example of constructor recursion
  // is the libc debug malloc, which is implemented in libc_malloc_debug_leak.so:
  // 1. The program depends on libc, so libc's constructor is called here.
  // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
  // 3. dlopen() calls the constructors on the newly created
  //    soinfo for libc_malloc_debug_leak.so.
  // 4. The debug .so depends on libc, so CallConstructors is
  //    called again with the libc soinfo. If it doesn't trigger the early-
  //    out above, the libc constructor will be called again (recursively!).
  constructors_called = true;

  if ((flags & FLAG_EXE) == 0 && preinit_array != NULL) {
    // The GNU dynamic linker silently ignores these, but we warn the developer.
    //PRINT("\"%s\": ignoring %zd-entry DT_PREINIT_ARRAY in shared library!",name, preinit_array_count);
  }

  // get_children().for_each([](soinfo* si) {
  //   si->CallConstructors();
  // });

  //TRACE("\"%s\": calling constructors", name);

  // DT_INIT should be called before DT_INIT_ARRAY if both are present.
  CallFunction("DT_INIT", init_func);
  CallArray("DT_INIT_ARRAY", init_array, init_array_count, false);
}

void soinfo::CallDestructors() {
  //TRACE("\"%s\": calling destructors", name);

  // DT_FINI_ARRAY must be parsed in reverse order.
  CallArray("DT_FINI_ARRAY", fini_array, fini_array_count, true);

  // DT_FINI should be called after DT_FINI_ARRAY if both are present.
  CallFunction("DT_FINI", fini_func);

  // This is needed on second call to dlopen
  // after library has been unloaded with RTLD_NODELETE
  constructors_called = false;
}

void soinfo::add_child(soinfo* child) {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return;
  }

  this->children.push_front(child);
  child->parents.push_front(this);
}

void soinfo::remove_all_links() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return;
  }

  // // 1. Untie connected soinfos from 'this'.
  // children.for_each([&] (soinfo* child) {
  //   child->parents.remove_if([&] (const soinfo* parent) {
  //     return parent == this;
  //   });
  // });

  // parents.for_each([&] (soinfo* parent) {
  //   parent->children.for_each([&] (const soinfo* child) {
  //     return child == this;
  //   });
  // });

  // 2. Once everything untied - clear local lists.
  parents.clear();
  children.clear();
}

void soinfo::set_st_dev(dev_t dev) {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return;
  }

  st_dev = dev;
}

void soinfo::set_st_ino(ino_t ino) {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return;
  }

  st_ino = ino;
}

dev_t soinfo::get_st_dev() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return 0;
  }

  return st_dev;
}

ino_t soinfo::get_st_ino() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return 0;
  }

  return st_ino;
}

// This is a return on get_children() in case
// 'this->flags' does not have FLAG_NEW_SOINFO set.
static soinfo::soinfo_list_t g_empty_list;

soinfo::soinfo_list_t& soinfo::get_children() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return g_empty_list;
  }

  return this->children;
}




