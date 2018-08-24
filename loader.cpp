#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <link.h>

#include "printlog.h"
#include "loader_addr.h"
#include "loader_phdr.h"
#include "loader_soinfo.h"
#include "linker_allocator.h"



#include "private/bionic_tls.h"
#include "private/KernelArgumentBlock.h"
#include "private/ScopedPthreadMutexLocker.h"
#include "private/ScopedFd.h"

#if COUNT_PAGES
static unsigned bitmask[4096];
#if defined(__LP64__)
#define MARK(offset) \
    do { \
        if ((((offset) >> 12) >> 5) < 4096) \
            bitmask[((offset) >> 12) >> 5] |= (1 << (((offset) >> 12) & 31)); \
    } while (0)
#else
#define MARK(offset) \
    do { \
        bitmask[((offset) >> 12) >> 3] |= (1 << (((offset) >> 12) & 7)); \
    } while (0)
#endif
#else
#define MARK(x) do {} while (0)
#endif

#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

static LinkerAllocator<soinfo> g_soinfo_allocator;
//static LinkerAllocator<LoaderListEntry<soinfo>> g_soinfo_links_allocator;


static soinfo* solist;
static soinfo* sonext;
static soinfo* somain; /* main process, always the one after libdl_info */

static const char* get_base_name(const char* name) {
  const char* bname = strrchr(name, '/');
  return bname ? bname + 1 : name;
}
#define SEARCH_NAME(x) get_base_name(x)

static soinfo g_realsi;
static loader_phdr g_elfreader;


static soinfo* soinfo_alloc(struct stat* file_stat) {

  //soinfo* si = g_soinfo_allocator.alloc();
  soinfo* si  = &g_realsi;
  // Initialize the new element.
  memset(si, 0, sizeof(soinfo));
  //strlcpy(si->name, name, sizeof(si->name));
  si->flags = FLAG_NEW_SOINFO;

  if (file_stat != NULL) {
    info_msg("file_stat->st_dev %d file_stat->st_ino %d \n",file_stat->st_dev , file_stat->st_ino );
    si->set_st_dev(file_stat->st_dev);
    si->set_st_ino(file_stat->st_ino);
    info_msg("file_stat->st_dev %d file_stat->st_ino %d \n",file_stat->st_dev , file_stat->st_ino );
  }

  init_msg("allocated soinfo @ %p\n", si);
  return si;
}


static ElfW(Sym)* soinfo_elf_lookup(soinfo* si, unsigned hash, const char* name) {
  ElfW(Sym)* symtab = si->symtab;
  const char* strtab = si->strtab;

  info_msg("SEARCH %s in %s@%p %x %zd\n",
             name, si->name, reinterpret_cast<void*>(si->base), hash, hash % si->nbucket);

  for (unsigned n = si->bucket[hash % si->nbucket], old_n = 0; n != 0; old_n = n, n = si->chain[n]) {
    ElfW(Sym)* s = symtab + n;
    if (n > si->nchain) {
        printf("%s: %s, n too large old %d, new %d\n", __func__, name, old_n, n);
        return NULL;
    }
    if (strcmp(strtab + s->st_name, name)) continue;

    /* only concern ourselves with global and weak symbol definitions */
    switch (ELF_ST_BIND(s->st_info)) {
      case STB_GLOBAL:
      case STB_WEAK:
        if (s->st_shndx == SHN_UNDEF) {
          continue;
        }

        info_msg("FOUND %s in %s (%p) %zd\n",
                 name, si->name, reinterpret_cast<void*>(s->st_value),
                 static_cast<size_t>(s->st_size));
        return s;
      case STB_LOCAL:
        continue;
      default:
        err_msg("ERROR: Unexpected ST_BIND value: %d for '%s' in '%s'\n",
            ELF_ST_BIND(s->st_info), name, si->name);
    }
  }

  warn_msg( "NOT FOUND %s in %s@%p %x %zd\n",name, si->name, reinterpret_cast<void*>(si->base), hash, hash % si->nbucket);

  return NULL;
}

static unsigned elfhash(const char* _name) {
    const unsigned char* name = reinterpret_cast<const unsigned char*>(_name);
    unsigned h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}
static ElfW(Sym)* soinfo_do_lookup(soinfo* si, const char* name, soinfo** lsi, soinfo* needed[]) {
    unsigned elf_hash = elfhash(name);
    ElfW(Sym)* s = NULL;
    if (si != NULL ){

        /* Look for symbols in the local scope (the object who is
         * searching). This happens with C++ templates on x86 for some
         * reason.
         *
         * Notes on weak symbols:
         * The ELF specs are ambiguous about treatment of weak definitions in
         * dynamic linking.  Some systems return the first definition found
         * and some the first non-weak definition.   This is system dependent.
         * Here we return the first definition found for simplicity.  */

        s = soinfo_elf_lookup(si, elf_hash, name);
        if (s != NULL) {
            *lsi = si;
            goto done;
        }
        
    }

    for (int i = 0; needed[i] != NULL; i++) {
        info_msg("%s: looking up %s in %s\n",
              si->name, name, needed[i]->name);
        s = soinfo_elf_lookup(needed[i], elf_hash, name);
        if (s != NULL) {
            *lsi = needed[i];
            goto done;
        }
    }

done:
    if (s != NULL) {
        info_msg( "si %s sym %s s->st_value = %p, "
                   "found in %s, base = %p, load bias = %p\n",
                   si->name, name, reinterpret_cast<void*>(s->st_value),
                   (*lsi)->name, reinterpret_cast<void*>((*lsi)->base),
                   reinterpret_cast<void*>((*lsi)->load_bias));
        return s;
    }

    return NULL;
}

static int soinfo_relocate(soinfo* si, ElfW(Rel)* rel, unsigned count, soinfo* needed[]) {
    ElfW(Sym)* s;
    soinfo* lsi;

    for (size_t idx = 0; idx < count; ++idx, ++rel) {
        unsigned type = ELFW(R_TYPE)(rel->r_info); 
        // TODO: don't use unsigned for 'sym'. Use uint32_t or ElfW(Addr) instead.
        unsigned sym = ELFW(R_SYM)(rel->r_info);
        ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rel->r_offset + si->load_bias);
        ElfW(Addr) sym_addr = 0;
        const char* sym_name = NULL;

        if (type == 0) { // R_*_NONE
            continue;
        }
        if (sym != 0) {
            sym_name = reinterpret_cast<const char*>(si->strtab + si->symtab[sym].st_name);
            s = soinfo_do_lookup(si, sym_name, &lsi, needed);
            if (s == NULL) {
                // We only allow an undefined symbol if this is a weak reference...
                s = &si->symtab[sym];
                if (ELF_ST_BIND(s->st_info) != STB_WEAK) {
                    err_msg("cannot locate symbol \"%s\" referenced by \"%s\"...\n", sym_name, si->name);
                    return -1;
                }

                /* IHI0044C AAELF 4.5.1.1:

                   Libraries are not searched to resolve weak references.
                   It is not an error for a weak reference to remain
                   unsatisfied.

                   During linking, the value of an undefined weak reference is:
                   - Zero if the relocation type is absolute
                   - The address of the place if the relocation is pc-relative
                   - The address of nominal base address if the relocation
                     type is base-relative.
                  */

                switch (type) {
#if defined(__arm__)
                case R_ARM_JUMP_SLOT:
                case R_ARM_GLOB_DAT:
                case R_ARM_ABS32:
                case R_ARM_RELATIVE:    /* Don't care. */
                    // sym_addr was initialized to be zero above or relocation
                    // code below does not care about value of sym_addr.
                    // No need to do anything.
                    break;
#elif defined(__i386__)
                case R_386_JMP_SLOT:
                case R_386_GLOB_DAT:
                case R_386_32:
                case R_386_RELATIVE:    /* Don't care. */
                    // sym_addr was initialized to be zero above or relocation
                    // code below does not care about value of sym_addr.
                    // No need to do anything.
                    break;
                case R_386_PC32:
                    sym_addr = reloc;
                    break;
#endif

#if defined(__arm__)
                case R_ARM_COPY:
                    // Fall through. Can't really copy if weak symbol is not found at run-time.
#endif
                default:
                    err_msg("unknown weak reloc type %d @ %p (%zu)\n", type, rel, idx);
                    return -1;
                }
            } else {
                // We got a definition.
                sym_addr = static_cast<ElfW(Addr)>(s->st_value + lsi->load_bias);
            }

        } else {
            s = NULL;
        }

        switch (type) {
#if defined(__arm__)
        case R_ARM_JUMP_SLOT:
            MARK(rel->r_offset);
            info_msg("RELO JMP_SLOT %08x <- %08x %s\n", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_ARM_GLOB_DAT:
            MARK(rel->r_offset);
            info_msg( "RELO GLOB_DAT %08x <- %08x %s\n", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_ARM_ABS32:
            MARK(rel->r_offset);
            info_msg("RELO ABS %08x <- %08x %s", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
            break;
        case R_ARM_REL32:
            MARK(rel->r_offset);
            info_msg( "RELO REL32 %08x <- %08x - %08x %s\n",
                       reloc, sym_addr, rel->r_offset, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr - rel->r_offset;
            break;
        case R_ARM_COPY:
            /*
             * ET_EXEC is not supported so this should not happen.
             *
             * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044d/IHI0044D_aaelf.pdf
             *
             * Section 4.7.1.10 "Dynamic relocations"
             * R_ARM_COPY may only appear in executable objects where e_type is
             * set to ET_EXEC.
             */
            info_msg("%s R_ARM_COPY relocations are not supported\n", si->name);
            return -1;
#elif defined(__i386__)
        case R_386_JMP_SLOT:
            MARK(rel->r_offset);
            info_msg( "RELO JMP_SLOT %08x <- %08x %s\n", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_386_GLOB_DAT:
            MARK(rel->r_offset);
            info_msg( "RELO GLOB_DAT %08x <- %08x %s\n", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_386_32:
            MARK(rel->r_offset);
            info_msg( "RELO R_386_32 %08x <- +%08x %s\n", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
            break;
        case R_386_PC32:
            MARK(rel->r_offset);
            info_msg("RELO R_386_PC32 %08x <- +%08x (%08x - %08x) %s\n",
                       reloc, (sym_addr - reloc), sym_addr, reloc, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr - reloc);
            break;
#elif defined(__mips__)
        case R_MIPS_REL32:
#if defined(__LP64__)
            // MIPS Elf64_Rel entries contain compound relocations
            // We only handle the R_MIPS_NONE|R_MIPS_64|R_MIPS_REL32 case
            if (ELF64_R_TYPE2(rel->r_info) != R_MIPS_64 ||
                ELF64_R_TYPE3(rel->r_info) != R_MIPS_NONE) {
                err__msg("Unexpected compound relocation type:%d type2:%d type3:%d @ %p (%zu)\n",
                       type, (unsigned)ELF64_R_TYPE2(rel->r_info),
                       (unsigned)ELF64_R_TYPE3(rel->r_info), rel, idx);
                return -1;
            }
#endif
            MARK(rel->r_offset);
            info_msg( "RELO REL32 %08zx <- %08zx %s\n", static_cast<size_t>(reloc),
                       static_cast<size_t>(sym_addr), sym_name ? sym_name : "*SECTIONHDR*");
            if (s) {
                *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
            } else {
                *reinterpret_cast<ElfW(Addr)*>(reloc) += si->base;
            }
            break;
#endif

#if defined(__arm__)
        case R_ARM_RELATIVE:
#elif defined(__i386__)
        case R_386_RELATIVE:
#endif
            MARK(rel->r_offset);
            if (sym) {
                err_msg("odd RELATIVE form...\n");
                return -1;
            }
            info_msg( "RELO RELATIVE %p <- +%p\n",
                       reinterpret_cast<void*>(reloc), reinterpret_cast<void*>(si->base));
            *reinterpret_cast<ElfW(Addr)*>(reloc) += si->base;
            break;

        default:
            err_msg("unknown reloc type %d @ %p (%zu)\n", type, rel, idx);
            return -1;
        }
    }
    return 0;
}

static bool soinfo_link_image(soinfo* si) {
    /* "base" might wrap around UINT32_MAX. */
    ElfW(Addr) base = si->load_bias;
    const ElfW(Phdr)* phdr = si->phdr;
    int phnum = si->phnum;
    bool relocating_linker = (si->flags & FLAG_LINKER) != 0;

    /* We can't debug anything until the linker is relocated */
    if (!relocating_linker) {
        info_msg("[ linking %s ]\n", si->name);
        info_msg("si->base = %p si->flags = 0x%08x\n", reinterpret_cast<void*>(si->base), si->flags);
    }

    /* Extract dynamic section */
    size_t dynamic_count;
    ElfW(Word) dynamic_flags;
    phdr_table_get_dynamic_section(phdr, phnum, base, &si->dynamic,
                                   &dynamic_count, &dynamic_flags);
    if (si->dynamic == NULL) {
        if (!relocating_linker) {
            info_msg("missing PT_DYNAMIC \n");
        }
        return false;
    } else {
        if (!relocating_linker) {
            info_msg("dynamic = %p\n", si->dynamic);
        }
    }

#if defined(__arm__)
    (void) phdr_table_get_arm_exidx(phdr, phnum, base,
                                    &si->ARM_exidx, &si->ARM_exidx_count);
#endif


   // Extract useful information from dynamic section.
    uint32_t needed_count = 0;
    for (ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
        info_msg("d = %p, d[0](tag) = %p d[1](val) = %p \n",
              d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
        switch (d->d_tag) {
        case DT_HASH:
            si->nbucket = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr)[0];
            si->nchain = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr)[1];
            si->bucket = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr + 8);
            si->chain = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr + 8 + si->nbucket * 4);
            break;
        case DT_STRTAB:
            si->strtab = reinterpret_cast<const char*>(base + d->d_un.d_ptr);
            break;
        case DT_SYMTAB:
            si->symtab = reinterpret_cast<ElfW(Sym)*>(base + d->d_un.d_ptr);
            break;
#if !defined(__LP64__)
        case DT_PLTREL:
            if (d->d_un.d_val != DT_REL) {
                info_msg("unsupported DT_RELA in \"%s\"\n", si->name);
                return false;
            }
            break;
#endif
        case DT_JMPREL:
#if defined(USE_RELA)
            si->plt_rela = reinterpret_cast<ElfW(Rela)*>(base + d->d_un.d_ptr);
#else
            si->plt_rel = reinterpret_cast<ElfW(Rel)*>(base + d->d_un.d_ptr);
#endif
            break;
        case DT_PLTRELSZ:
#if defined(USE_RELA)
            si->plt_rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
#else
            si->plt_rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
            break;
#if defined(__mips__)
        case DT_PLTGOT:
            // Used by mips and mips64.
            si->plt_got = reinterpret_cast<ElfW(Addr)**>(base + d->d_un.d_ptr);
            break;
#endif
        case DT_DEBUG:
            // Set the DT_DEBUG entry to the address of _r_debug for GDB
            // if the dynamic table is writable
// FIXME: not working currently for N64
// The flags for the LOAD and DYNAMIC program headers do not agree.
// The LOAD section containng the dynamic table has been mapped as
// read-only, but the DYNAMIC header claims it is writable.
// #if !(defined(__mips__) && defined(__LP64__))
//             if ((dynamic_flags & PF_W) != 0) {
//                 d->d_un.d_val = reinterpret_cast<uintptr_t>(&_r_debug);
//             }
//             break;
// #endif
            break;
#if defined(USE_RELA)
         case DT_RELA:
            si->rela = reinterpret_cast<ElfW(Rela)*>(base + d->d_un.d_ptr);
            break;
         case DT_RELASZ:
            si->rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
            break;
        case DT_REL:
            init_msg("unsupported DT_REL in \"%s\"\n", si->name);
            return false;
        case DT_RELSZ:
            init_msg("unsupported DT_RELSZ in \"%s\"\n", si->name);
            return false;
#else
        case DT_REL:
            si->rel = reinterpret_cast<ElfW(Rel)*>(base + d->d_un.d_ptr);
            break;
        case DT_RELSZ:
            si->rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
            break;
         case DT_RELA:
            info_msg("unsupported DT_RELA in \"%s\"\n", si->name);
            return false;
#endif
        case DT_INIT:
            si->init_func = reinterpret_cast<linker_function_t>(base + d->d_un.d_ptr);
            info_msg("%s constructors (DT_INIT) found at %p\n", si->name, si->init_func);
            break;
        case DT_FINI:
            si->fini_func = reinterpret_cast<linker_function_t>(base + d->d_un.d_ptr);
            info_msg("%s destructors (DT_FINI) found at %p\n", si->name, si->fini_func);
            break;
        case DT_INIT_ARRAY:
            si->init_array = reinterpret_cast<linker_function_t*>(base + d->d_un.d_ptr);
            info_msg("%s constructors (DT_INIT_ARRAY) found at %p\n", si->name, si->init_array);
            break;
        case DT_INIT_ARRAYSZ:
            si->init_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
            break;
        case DT_FINI_ARRAY:
            si->fini_array = reinterpret_cast<linker_function_t*>(base + d->d_un.d_ptr);
            info_msg("%s destructors (DT_FINI_ARRAY) found at %p\n", si->name, si->fini_array);
            break;
        case DT_FINI_ARRAYSZ:
            si->fini_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
            break;
        case DT_PREINIT_ARRAY:
            si->preinit_array = reinterpret_cast<linker_function_t*>(base + d->d_un.d_ptr);
            info_msg("%s constructors (DT_PREINIT_ARRAY) found at %p\n", si->name, si->preinit_array);
            break;
        case DT_PREINIT_ARRAYSZ:
            si->preinit_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
            break;
        case DT_TEXTREL:
#if defined(__LP64__)
            info_msg("text relocations (DT_TEXTREL) found in 64-bit ELF file \"%s\"\n", si->name);
            return false;
#else
            si->has_text_relocations = true;
            break;
#endif
        case DT_SYMBOLIC:
            si->has_DT_SYMBOLIC = true;
            break;
        case DT_NEEDED:
            ++needed_count;
            break;
        case DT_FLAGS:
            if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
                info_msg("text relocations (DF_TEXTREL) found in 64-bit ELF file \"%s\"\n", si->name);
                return false;
#else
                si->has_text_relocations = true;
#endif
            }
            if (d->d_un.d_val & DF_SYMBOLIC) {
                si->has_DT_SYMBOLIC = true;
            }
            break;


        default:
            info_msg("Unused DT entry: type %p arg %p \n",
                  reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
            break;
        }
    }

     soinfo** needed = reinterpret_cast<soinfo**>(alloca((1+needed_count) * sizeof(soinfo*)));
     soinfo** pneeded = needed;

     for (ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
         if (d->d_tag == DT_NEEDED) {
             const char* library_name = si->strtab + d->d_un.d_val;

             void *handle = dlopen(library_name,RTLD_NOW);
             if(handle ==NULL){
                  break;
             }
             soinfo *tsi= (soinfo*)handle;
             init_msg("needs %s base 0x%08x\n",library_name,tsi->base);
             if(tsi->base!=0){
                 *pneeded++ = tsi;
              }else{
                 *pneeded++ = NULL;
              }
             //dlclose(handle); 
         }
     }   
    pneeded = NULL;
    
#if defined(USE_RELA)
    if (si->plt_rela != NULL) {
         // debug_msg("[ relocating %s plta ]\n", si->name);
        if (soinfo_relocate(si, si->plt_rela, si->plt_rela_count, needed)) {
            return false;
        }
    }
    if (si->rela != NULL) {
         // debug_msg("[ relocating %s a]\n", si->name);
        if (soinfo_relocate(si, si->rela, si->rela_count, needed)) {
            return false;
        }
    }
#else
    if (si->plt_rel != NULL) {
         // debug_msg("[ relocating %s plt]\n", si->name);
        if (soinfo_relocate(si, si->plt_rel, si->plt_rel_count, needed)) {
            return false;
        }
    }
    if (si->rel != NULL) {
         // debug_msg("[ relocating %s ]\n", si->name);
        if (soinfo_relocate(si, si->rel, si->rel_count, needed)) {
            return false;
        }
    }
#endif   
    debug_msg("[  %s finished ]\n", __func__);
    return true;
}


static loader_addr g_loaderaddr;

static void decrypt_data(const unsigned char *key ,unsigned char *data ,int len )
{

}


void  start_load(void)
{
    unsigned char key[64];
    Elf32_Addr  keyaddr=0;
    Elf32_Addr  Soaddr = 0;
    Elf32_Ehdr  Self_elfHeader;
    Elf32_Ehdr  real_elfHeader;
  //open combine so (loader.so and origin so included);
    void *handle =dlopen("libfirstshared.so",RTLD_NOW);

    soinfo *selfsi= (soinfo*)handle;

    init_msg("dlopen #########################  00\n");
    init_msg("tso base 0x%08x\n",selfsi->base);
    init_msg("tso phdr 0x%08x\n",selfsi->phdr);
    init_msg("tso strtab 0x%08x\n",selfsi->strtab);
    init_msg("tso %s\n",&selfsi->strtab[0]);
    init_msg("tso %s\n",&selfsi->strtab[1]);
    init_msg("tso load_bias %x\n",selfsi->load_bias);
    init_msg("tso dynamic %x\n",selfsi->dynamic);

    Elf32_Addr soinfo_addr =(Elf32_Addr)selfsi; 
    init_msg("soinfo_addr 0x%08x \n",soinfo_addr);
    Elf32_Addr start_addr = PAGE_START(soinfo_addr);
    init_msg("soinfo_addr 0x%08x \n",start_addr);

    //find offset of origin so in combine so. 
    g_loaderaddr.load_needed_elfhead((unsigned char *)selfsi->base,&Self_elfHeader);
    keyaddr = Self_elfHeader.e_shoff+selfsi->base;
    Soaddr  = keyaddr+64;
    init_msg("keyaddr 0x%08x \n",keyaddr);
    init_msg("Soaddr 0x%08x \n",Soaddr);

    memcpy(&real_elfHeader,(void *)Soaddr,sizeof(Elf32_Ehdr));
    init_msg("real_elfHeader  e_ident 0x%02x \n",real_elfHeader.e_ident[0]);

    //load key

    memcpy(key,(void *)keyaddr,sizeof(key));
    //decrypt so

    decrypt_data(key,(unsigned char *)Soaddr,real_elfHeader.e_shoff);
    
    //load map 
    g_elfreader.load(Soaddr);
    soinfo* si = soinfo_alloc(NULL);
    if(si==NULL){
        err_msg("soinfo_alloc faild\n");
    }

    si->base = g_elfreader.load_start();
    si->size = g_elfreader.load_size();
    si->load_bias = g_elfreader.load_bias();
    si->phnum = g_elfreader.phdr_count();
    si->phdr = g_elfreader.loaded_phdr();

    init_msg("[ load_library base=%p size=%zu name='%s' ]\n",
            reinterpret_cast<void*>(si->base), si->size, si->name);
    soinfo_link_image(si);

    if(si != NULL) {
      si->CallConstructors();
    }
    // mprotect((void*)start_addr,PAGE_SIZE,PROT_READ | PROT_WRITE);

    // ttsi->ARM_exidx =si->ARM_exidx;
    // ttsi->ARM_exidx_count =si->ARM_exidx_count;
    // ttsi->base = si->base ;
    // ttsi->size   = si->size;
    // ttsi->load_bias =si->load_bias;
    // ttsi->phnum = si->phnum;
    // ttsi->phdr = si->phdr;
    // ttsi->strtab = si->strtab;
    // ttsi->symtab = si->symtab ;
    // ttsi->dynamic = si->dynamic;
    // ttsi->nbucket =si->nbucket;
    // ttsi->nchain =si->nchain ;
    // ttsi->bucket =si->bucket;
    // ttsi->chain =si->chain; 
    // ttsi->plt_rel=si->plt_rel;
    // ttsi->plt_rel_count=si->plt_rel_count;
    // ttsi->rel = si->rel;
    // ttsi->rel_count  = si->rel_count ; 
    // mprotect((void*)start_addr,PAGE_SIZE,PROT_READ);
    unsigned int addr=0;
    int libkersize =0;
    g_loaderaddr.openmaps();
    soinfo *elf_main,elfmain;
    elf_main=&elfmain;
    memset(&elfmain,0,sizeof(soinfo));

    if((addr = g_loaderaddr.getParsePage("demo.out",&libkersize))!=0){

      g_loaderaddr.load_needed_soinfo(elf_main,(unsigned char *)addr,libkersize);
      
      init_msg("###################################  demo\n");
      init_msg("tso base 0x%08x\n",elf_main->base);
      init_msg("tso phdr 0x%08x\n",elf_main->phdr);
      init_msg("tso strtab 0x%08x\n",elf_main->strtab);
      init_msg("tso %s\n",&elf_main->strtab[0]);
      init_msg("tso %s\n",&elf_main->strtab[1]);
      init_msg("tso load_bias %x\n",elf_main->load_bias);
      init_msg("tso dynamic %x\n",elf_main->dynamic);

      g_loaderaddr.load_relocate(elf_main,si);
    
    }
    g_loaderaddr.closemaps();

      
    return ;
}
extern "C" void _print_constructor(void)
{
    init_msg("%s \n",__func__ );
}
void print_start(void)
{
    printf("%s jius his zhem wan dan\n",__func__ );
}
extern "C" void _init(void)
{
     init_msg("%s\n",__func__);
     start_load();
}

int g_val=1;

extern "C" void mysection_func(void)
{
  printf("%s g_val %d \n",__func__,g_val );
}
extern "C" void mysection2_func(void)
{
  printf("%s g_val %d \n",__func__,g_val );
}
