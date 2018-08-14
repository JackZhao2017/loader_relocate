
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  
#include <sys/types.h>  
#include <elf.h>  
#include <sys/mman.h> 
#include <dlfcn.h>
#include "printlog.h"
#include "loader_addr.h"
#include "loader_soinfo.h"

//const char linkername[]="addr.out";

// typedef struct 
// {
//       unsigned int startaddr;
//       unsigned int endaddr;
//       unsigned int prop;
//       unsigned int offset;


// };
#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

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



static char  func_name[3][32]={
      "mysection2_func",
      "mysection_func",
      NULL
};

loader_addr::loader_addr()
{
    relocate_minaddr = 0xffffffff;
    relocate_maxaddr = 0;
    mfp = NULL;
}
loader_addr::~loader_addr()
{

}
int  loader_addr::openmaps(void)
{
    char buf[128];
    mPid= getpid(); 
    init_msg("%d\n",mPid );
    sprintf(buf, "/proc/%d/maps", mPid); 
    mfp =fopen(buf, "r"); 
    if(mfp == NULL)  
    {  
      debug_msg("open failed");  
      goto _error;  
    }  
    relocate_minaddr = 0xffffffff;
    relocate_maxaddr = 0;
    return 0;
_error:  
    fclose(mfp); 
    mfp = NULL;
    return -1;    
}

void loader_addr::closemaps(void)
{
    debug_msg("closemaps\n");
    fclose(mfp); 
    mfp = NULL;
}



unsigned int loader_addr::getParsePage(const char * name,int *size)
{
    char buf[4096], *temp,*temp1;  
    unsigned int  minaddr=0,max=0;
    while(fgets(buf, sizeof(buf), mfp))
    {
        if(name!=NULL){
          if(strstr(buf, name)){
              debug_msg("%s",buf);
              temp = strtok(buf, " ");  
              debug_msg("%s\n", temp);

              temp1= strtok(temp,"-");
              debug_msg("%s\n", temp1);
              minaddr  = strtoul(temp1, NULL, 16);  

              temp1= strtok(NULL,"-");
              debug_msg("%s\n", temp1);
              max  = strtoul(temp1, NULL, 16);
              *size= max - minaddr;
              break;  
          }
        }else{
          if(strstr(buf, "linker"))
          {
              debug_msg("%s",buf);
              continue;
          }
          else if(strstr(buf, "so")){
              debug_msg("%s",buf);
              continue;
          }
          else if(strstr(buf, "/")){
              debug_msg("%s",buf);
              continue;
          }
          else if(strstr(buf, "/dev")){
              debug_msg("%s",buf);
              continue;
          }
          else if(strstr(buf, "[heap]")){
              debug_msg("%s",buf);
              continue;
          }
          else if(strstr(buf, "[stack]")){
              debug_msg("%s",buf);
              continue;
          }
          else if(strstr(buf, "[vectors]")){
              debug_msg("%s",buf);
              continue;
          }
          else {
              debug_msg("%s",buf);
              temp = strtok(buf, " ");  
              //debug_msg("%s\n", temp);

              temp1= strtok(temp,"-");
              //debug_msg("%s\n", temp1);
              minaddr  = strtoul(temp1, NULL, 16);  

              temp1= strtok(NULL,"-");
              //debug_msg("%s\n", temp1);
              max  = strtoul(temp1, NULL, 16);
              *size= max - minaddr;
              break;
          }
        }
    }
    return minaddr; 
}

unsigned char *  loader_addr::datastr(unsigned char *data,int size, const char *str ,int strsize)
{
    int i=0,j=0;
    const char *tmpstr=str;
    unsigned char * start_addr=NULL;
    unsigned char *  ret_addr=NULL;
    for(i=0;i<size;i++){
        if(data[i]!=tmpstr[j]){
          j=0;
          continue;
        }
        start_addr =&data[i];
        if(++j==strsize){
          ret_addr = start_addr;
          break;
        }
    }
    return ret_addr;
}

void loader_addr::load_needed_elfhead(unsigned char *data)
{
    memcpy(&mElf_Header,data,sizeof(Elf32_Ehdr));
    debug_msg("phdr offset 0x%x \n",mElf_Header.e_phoff);

}

void loader_addr::load_needed_phdr(unsigned char *data,int size)
{
    if(size<1024){
      err_msg("not enough infomation\n");
      return;
    }
    
    load_needed_elfhead(data);
    mPhdr_num = mElf_Header.e_phnum;

    phdr_table_ = reinterpret_cast<Elf32_Phdr*>(reinterpret_cast<unsigned char*>(data) +mElf_Header.e_phoff);

}

void loader_addr::load_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias,
                                    ElfW(Dyn)** dynamic, size_t* dynamic_count, ElfW(Word)* dynamic_flags) {
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_DYNAMIC) {
      continue;
    }

    *dynamic = reinterpret_cast<ElfW(Dyn)*>(load_bias + phdr->p_vaddr);
    if (dynamic_count) {
      *dynamic_count = (unsigned)(phdr->p_memsz / 8);
    }
    if (dynamic_flags) {
      *dynamic_flags = phdr->p_flags;
    }
    info_msg("find dynamic\n");
    return;
  }
}


int  loader_addr::load_needed_so_imag(soinfo* si)
{
      ElfW(Addr) base = si->load_bias;
      const ElfW(Phdr)* phdr = si->phdr;
      int phnum = si->phnum;
      size_t dynamic_count;
      ElfW(Word) dynamic_flags;


      load_dynamic_section(phdr,phnum,base,&si->dynamic,&dynamic_count,&dynamic_flags);

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
                return -1;
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
        }
      }
      return 0;
}

static ElfW(Sym)* elf_lookup(soinfo* si, unsigned hash, const char* name) {
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

        debug_msg("FOUND %s in %s (%p) %zd\n",
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

void loader_addr::load_needed_soinfo(soinfo* si ,unsigned char *data,int size)
{
    //load_needed_elfhead(data);
    load_needed_phdr(data, size);
    si->load_bias = (ElfW(Addr))data;
    si->phnum=mPhdr_num;
    si->phdr = phdr_table_;  
    load_needed_so_imag(si);
}
ElfW(Sym)* loader_addr::lookup_soinfo(const char* name,soinfo* needed)
{     
     for(int i=0;i<3;i++)
     {
          if(strcmp(func_name[i],name)==0)
          {
              debug_msg("%s  name %s\n",func_name[i],name );
              goto _done;
          }
     }
     return NULL;

_done:
     unsigned elf_hash = elfhash(name);
     ElfW(Sym)* s = NULL;
     s = elf_lookup(needed, elf_hash, name);
     if(s!=NULL){
        return s;
     }
     return NULL;

}


int loader_addr::relocate_soinfo(soinfo* si, ElfW(Rel)* rel, unsigned count, soinfo* needed)
{
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
            // debug_msg("%s  sym_name %s\n",__func__,sym_name );
            s = lookup_soinfo(sym_name,needed);
            if (s == NULL) {
                continue;
            } else {
                // We got a definition.
                sym_addr = static_cast<ElfW(Addr)>(s->st_value + needed->load_bias);
            }

        } else {
            continue ;
        }

        switch (type) {
#if defined(__arm__)
        case R_ARM_JUMP_SLOT:
            MARK(rel->r_offset); 
            debug_msg("RELO JMP_SLOT %08x <- %08x %s\n", reloc, sym_addr, sym_name);        
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;         
            break;
        case R_ARM_GLOB_DAT:
            MARK(rel->r_offset);
            debug_msg( "RELO GLOB_DAT %08x <- %08x %s\n", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_ARM_ABS32:
            MARK(rel->r_offset);
            debug_msg("RELO ABS %08x <- %08x %s", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
            break;
        case R_ARM_REL32:
            MARK(rel->r_offset);
            debug_msg( "RELO REL32 %08x <- %08x - %08x %s\n",
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

ElfW(Addr) loader_addr::relocate_infopage(soinfo* si, ElfW(Rel)* rel ,unsigned count)
{
     ElfW(Addr) min=0xffffffff,max=0,addr;
     for (size_t idx = 0; idx < count; ++idx, ++rel)
     {
          addr = rel->r_offset + si->load_bias;
          if(addr<min){
             min= addr;
          }
          if(addr>max){
             max =addr; 
          }
     }
     if(relocate_minaddr>min)
     {
        relocate_minaddr = min;
     }      
     if(relocate_maxaddr<max)
     {
        relocate_maxaddr = max;
     }

     return min;
}

int  loader_addr::load_relocate(soinfo* si,soinfo *needed)
{

    if (si->plt_rel != NULL)
          relocate_infopage(si, si->plt_rel, si->plt_rel_count);

    if (si->rel != NULL)
          relocate_infopage(si, si->rel, si->rel_count);

    Elf32_Addr start_addr= PAGE_START(relocate_minaddr); 



    int page_size = (relocate_maxaddr - relocate_minaddr)/PAGE_SIZE+1;

    debug_msg("%s start addr %x relocate_minaddr %x  relocate_maxaddr %x page_size %d \n",__func__,start_addr,relocate_minaddr,relocate_maxaddr,page_size);

    mprotect((void*)start_addr,PAGE_SIZE*page_size,PROT_READ | PROT_WRITE);

    if (si->plt_rel != NULL) {

        debug_msg("[ relocating %s plt]\n", si->name);
        
        if (relocate_soinfo(si, si->plt_rel, si->plt_rel_count, needed)) {
            goto err;
        }
    }

    if (si->rel != NULL) {

        debug_msg("[ relocating %s ]\n", si->name);

        if (relocate_soinfo(si, si->rel, si->rel_count, needed)) {
            goto err;
        }
    }

    mprotect((void*)start_addr,PAGE_SIZE*page_size,PROT_READ );

    return true;
err:
    mprotect((void*)start_addr,PAGE_SIZE*page_size,PROT_READ );
    return false;
}




// int main(int argc, char const *argv[])
// {
//   int size;
//   unsigned int addr=0;
//   loader_addr loaderaddr;
//   loaderaddr.openmaps();
//   unsigned char * so_addr=NULL;
//   while((addr = loaderaddr.getParsePage("libc",&size))!=0)
//   {
//       debug_msg("addr 0x%x  size %d \n",addr,size);
//       //unsigned char * sub =loaderaddr.datastr((unsigned char *)addr,size,"libc.so",strlen("libc.so"));
//       if(addr!=NULL)
//       {
//           so_addr=(unsigned char *)addr;
//           printf("addr 0x%x\n",addr);
//           break;
//       }
//   }
//   soinfo neededsi;
//   loaderaddr.load_needed_soinfo(&neededsi,(unsigned char *)so_addr,size);
//   loaderaddr.closemaps();
//   while(1)
//   {
//     sleep(1);
//   }
//   return 0;
// }


