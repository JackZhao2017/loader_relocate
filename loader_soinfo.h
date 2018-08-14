#ifndef _USER_LOADER_SOINFO_H_
#define _USER_LOADER_SOINFO_H_

// #ifdef __cplusplus
// extern "C" {
// #endif

#include <elf.h>
#include <link.h>
#include <unistd.h>
#include <sys/stat.h>
#include <inttypes.h>

// #include "loader_list.h"
#include "private/libc_logging.h"
#include "private/bionic_macros.h"



#define SOINFO_NAME_LEN 128


#define FLAG_LINKED     0x00000001
#define FLAG_EXE        0x00000004 // The main executable
#define FLAG_LINKER     0x00000010 // The linker itself
#define FLAG_NEW_SOINFO 0x40000000 // new soinfo format

typedef void (*linker_function_t)();

struct soinfo;

// class SoinfoListAllocator {
// public:
//   static LoaderListEntry<soinfo>* alloc();
//   static void free(LoaderListEntry<soinfo>* entry);
// private:
//   // unconstructable
//   DISALLOW_IMPLICIT_CONSTRUCTORS(SoinfoListAllocator);
// };


struct soinfo {
 public:
  // typedef LoaderList<soinfo, SoinfoListAllocator> soinfo_list_t;
 public:
  char name[SOINFO_NAME_LEN];
  const ElfW(Phdr)* phdr;
  size_t phnum;
  ElfW(Addr) entry;
  ElfW(Addr) base;
  size_t size;

// #ifndef __LP64__
  uint32_t unused1;  // DO NOT USE, maintained for compatibility.
// #endif

  ElfW(Dyn)* dynamic;

// #ifndef __LP64__
  uint32_t unused2; // DO NOT USE, maintained for compatibility
  uint32_t unused3; // DO NOT USE, maintained for compatibility
// #endif

  soinfo* next;
  unsigned flags;

  const char* strtab;
  ElfW(Sym)* symtab;

  size_t nbucket;
  size_t nchain;
  unsigned* bucket;
  unsigned* chain;

  unsigned* plt_got;

// #if defined(__mips__) || !defined(__LP64__)
//   // This is only used by mips and mips64, but needs to be here for
//   // all 32-bit architectures to preserve binary compatibility.
//   ElfW(Addr)** plt_got;
// #endif



  ElfW(Rel)* plt_rel;
  size_t plt_rel_count;

  ElfW(Rel)* rel;
  size_t rel_count;


  linker_function_t* preinit_array;
  size_t preinit_array_count;

  linker_function_t* init_array;
  size_t init_array_count;
  linker_function_t* fini_array;
  size_t fini_array_count;

  linker_function_t init_func;
  linker_function_t fini_func;

#if defined(__arm__)
  // ARM EABI section used for stack unwinding.
  unsigned* ARM_exidx;
  size_t ARM_exidx_count;
#elif defined(__mips__)
  unsigned mips_symtabno;
  unsigned mips_local_gotno;
  unsigned mips_gotsym;
#endif

  size_t ref_count;
  link_map link_map_head;

  bool constructors_called;

  // When you read a virtual address from the ELF file, add this
  // value to get the corresponding address in the process' address space.
  ElfW(Addr) load_bias;

#if !defined(__LP64__)
  bool has_text_relocations;
#endif
  bool has_DT_SYMBOLIC;
  void CallConstructors();
  void CallDestructors();
  void CallPreInitConstructors();

  void add_child(soinfo* child);
  void remove_all_links();

  void set_st_dev(dev_t st_dev);
  void set_st_ino(ino_t st_ino);
  ino_t get_st_ino();
  dev_t get_st_dev();

  // soinfo_list_t& get_children();

 private:
  void CallArray(const char* array_name, linker_function_t* functions, size_t count, bool reverse);
  void CallFunction(const char* function_name, linker_function_t function);

 private:
  // This part of the structure is only available
  // when FLAG_NEW_SOINFO is set in this->flags.
  unsigned int version;

  dev_t st_dev;
  ino_t st_ino;

  // dependency graph
  // soinfo_list_t children;
  // soinfo_list_t parents;

};
// #ifdef __cplusplus
// };
// #endif


#endif