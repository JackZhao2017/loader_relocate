#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/mman.h>
#include "loader_phdr.h"
#include "printlog.h"


#define PAGE_SIZE  4096
#define PAGE_MASK  (~(PAGE_SIZE-1))

// Returns the address of the page containing address 'x'.
#define PAGE_START(x)  ((x) & PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

loader_phdr::loader_phdr(Elf32_Addr base)
{
	memset(&elf_header,0,sizeof(Elf32_Ehdr));
	phdr_num_=0;
	mfd=fd;
  mbase =0;
}

loader_phdr::~loader_phdr()
{

}

bool loader_phdr::ReadElfHeader()
{
	//read(mfd,&elf_header,sizeof(Elf32_Ehdr));
	//memcpy(&elf_header,base,sizeof(Elf32_Ehdr));
	return true;
}


bool loader_phdr::VerifyElfHeader(){
	if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
		err_msg(" has bad ELF magic\n");
		return false;
	}
	return true;
}

bool loader_phdr::ReadProgramHeader() 
{
	phdr_num_ = elf_header.e_phnum;

	if(phdr_num_ < 1 || phdr_num_ > 65536/sizeof(Elf32_Phdr)) {
		err_msg(" has invalid e_phnum: %zd", phdr_num_);
		return false;
	}

	Elf32_Addr page_min = PAGE_START(elf_header.e_phoff);
	Elf32_Addr page_max = PAGE_END(elf_header.e_phoff + (phdr_num_*sizeof(Elf32_Phdr)));
	Elf32_Addr page_offset = PAGE_OFFSET(elf_header.e_phoff);
	phdr_size_ = page_max - page_min;

	void* mmap_result = mmap(NULL, phdr_size_, PROT_READ, MAP_PRIVATE, mfd, page_min);
	if (mmap_result == MAP_FAILED) {
		err_msg("phdr mmap failed: %s\n", strerror(errno));
		return false;
	}
  phdr_mmap_ = mmap_result;
 	phdr_table_ = reinterpret_cast<Elf32_Phdr*>(reinterpret_cast<char*>(mmap_result) + page_offset);
	info_msg("mmap_result 0x%08x   phdr_table_  0x%08x\n",mmap_result,(void *)phdr_table_);
	return true;
}
static size_t phdr_table_get_load_size(const Elf32_Phdr* phdr_table, size_t phdr_count,
                                Elf32_Addr* out_min_vaddr,
                                Elf32_Addr* out_max_vaddr) {
  Elf32_Addr min_vaddr = 0xffffffff;
  Elf32_Addr max_vaddr = 0;

  bool found_pt_load = false;
  for (size_t i = 0; i < phdr_count; ++i) {
    const Elf32_Phdr* phdr = &phdr_table[i];

    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    found_pt_load = true;

    if (phdr->p_vaddr < min_vaddr) {
      min_vaddr = phdr->p_vaddr;
    }

    if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
      max_vaddr = phdr->p_vaddr + phdr->p_memsz;
    }
  }
  if (!found_pt_load) {
    min_vaddr = 0;
  }

  min_vaddr = PAGE_START(min_vaddr);
  max_vaddr = PAGE_END(max_vaddr);

  if (out_min_vaddr != NULL) {
    *out_min_vaddr = min_vaddr;
  }
  if (out_max_vaddr != NULL) {
    *out_max_vaddr = max_vaddr;
  }
  return max_vaddr - min_vaddr;
}
bool loader_phdr::ReserveAddressSpace() {
	Elf32_Addr min_vaddr;
	Elf32_Addr max_vaddr;
	load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr,&max_vaddr);
	if (load_size_ == 0) {
		err_msg(" has no loadable segments\n");
		return false;
	}

	uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);
	void* start;

	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
	start = mmap(addr, load_size_, PROT_NONE, mmap_flags, -1, 0);
	if (start == MAP_FAILED) {
	  err_msg("couldn't reserve %zd bytes of address space for\n", load_size_);
	  return false;
	}


	load_start_ = start;
	load_bias_ = reinterpret_cast<uint8_t*>(start) - addr;
	init_msg("load_size_ %x \n",load_size_ );
	init_msg("start 0x%x  load_bias_  0x%x\n",start,load_bias_);
	return true;
}
bool loader_phdr::loadSegments()
{
	 for (size_t i = 0; i < phdr_num_; ++i) {
    const Elf32_Phdr* phdr = &phdr_table_[i];

    if (phdr->p_type != PT_LOAD) {
      continue;
    }

    // Segment addresses in memory.
    Elf32_Addr seg_start = phdr->p_vaddr + load_bias_;
    Elf32_Addr seg_end   = seg_start + phdr->p_memsz;

    Elf32_Addr seg_page_start = PAGE_START(seg_start);
    Elf32_Addr seg_page_end   = PAGE_END(seg_end);

    Elf32_Addr seg_file_end   = seg_start + phdr->p_filesz;

    // File offsets.
    Elf32_Addr file_start = phdr->p_offset;
    Elf32_Addr file_end   = file_start + phdr->p_filesz;

    Elf32_Addr file_page_start = PAGE_START(file_start);
    Elf32_Addr file_length = file_end - file_page_start;

    info_msg(" seg_start  	0x%08x \n",seg_start);
    info_msg(" seg_end  		0x%08x \n", seg_end);
	  info_msg(" seg_page_start 0x%08x  \n", seg_page_start);
	  info_msg(" seg_page_end 	0x%08x  \n",seg_page_end);
	  info_msg(" seg_file_end 	0x%08x \n",seg_file_end);
    info_msg(" file_start 	0x%08x  \n",file_start);
    info_msg(" file_end 		0x%08x   \n",file_end );
    info_msg(" file_page_start 0x%08x   \n",file_page_start );
    info_msg(" file_length 	0x%08x \n",file_length );

    if (file_length != 0) {
      void* seg_addr = mmap(reinterpret_cast<void*>(seg_page_start),
                            file_length,
                            PFLAGS_TO_PROT(phdr->p_flags),
                            MAP_FIXED|MAP_PRIVATE,
                            mfd,
                            file_page_start);
      init_msg(" %d seg_addr  0x%08x  len %d \n",i,seg_addr,file_length);
      if (seg_addr == MAP_FAILED) {
        err_msg("couldn't map segment %zd: %s", i, strerror(errno));
        return false;
      }
    }

    // if the segment is writable, and does not end on a page boundary,
    // zero-fill it until the page limit.
    if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
         memset(reinterpret_cast<void*>(seg_file_end), 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
    }

    seg_file_end = PAGE_END(seg_file_end);

    // seg_file_end is now the first page address after the file
    // content. If seg_end is larger, we need to zero anything
    // between them. This is done by using a private anonymous
    // map for all extra pages.
    if (seg_page_end > seg_file_end) {
	      void* zeromap = mmap(reinterpret_cast<void*>(seg_file_end),
	                           seg_page_end - seg_file_end,
	                           PFLAGS_TO_PROT(phdr->p_flags),
	                           MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
	                           -1,
	                           0);
	      init_msg(" %d zeromap   0x%08x  len  %d \n",i,zeromap,seg_page_end - seg_file_end);
	      if (zeromap == MAP_FAILED) {
	        err_msg("couldn't zero fill  gap: %s", strerror(errno));
	        return false;
	      }
    }
  }
  return true;
}

// Returns the address of the program header table as it appears in the loaded
// segments in memory. This is in contrast with 'phdr_table_' which
// is temporary and will be released before the library is relocated.
bool loader_phdr::FindPhdr() {
  const Elf32_Phdr* phdr_limit = phdr_table_ + phdr_num_;

  // If there is a PT_PHDR, use it directly.
  for (const Elf32_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
    if (phdr->p_type == PT_PHDR) {
      return CheckPhdr(load_bias_ + phdr->p_vaddr);
    }
  }

  // Otherwise, check the first loadable segment. If its file offset
  // is 0, it starts with the ELF header, and we can trivially find the
  // loaded program header from it.
  for (const Elf32_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
    if (phdr->p_type == PT_LOAD) {
      if (phdr->p_offset == 0) {
        Elf32_Addr  elf_addr = load_bias_ + phdr->p_vaddr;
        const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr*>(elf_addr);
        Elf32_Addr  offset = ehdr->e_phoff;
        return CheckPhdr((Elf32_Addr)ehdr + offset);
      }
      break;
    }
  }

  err_msg("can't find loaded phdr for \n");
  return false;
}
bool loader_phdr::CheckPhdr(Elf32_Addr loaded) {
  const Elf32_Phdr* phdr_limit = phdr_table_ + phdr_num_;
  Elf32_Addr loaded_end = loaded + (phdr_num_ * sizeof(Elf32_Phdr));
  for (Elf32_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    Elf32_Addr seg_start = phdr->p_vaddr + load_bias_;
    Elf32_Addr seg_end = phdr->p_filesz + seg_start;
    if (seg_start <= loaded && loaded_end <= seg_end) {
      loaded_phdr_ = reinterpret_cast<const Elf32_Phdr*>(loaded);
      return true;
    }
  }
  err_msg("loaded phdr %p not in loadable segment\n",  reinterpret_cast<void*>(loaded));
  return false;
}

bool loader_phdr::load()
{
	return ReadElfHeader()&&VerifyElfHeader()&&ReadProgramHeader()&&ReserveAddressSpace()&&loadSegments()&&FindPhdr(); 
}


void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
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
    return;
  }
  *dynamic = NULL;
  if (dynamic_count) {
    *dynamic_count = 0;
  }
}


#if defined(__arm__)

#  ifndef PT_ARM_EXIDX
#    define PT_ARM_EXIDX    0x70000001      /* .ARM.exidx segment */
#  endif

/* Return the address and size of the .ARM.exidx section in memory,
 * if present.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   arm_exidx       -> address of table in memory (NULL on failure).
 *   arm_exidx_count -> number of items in table (0 on failure).
 * Return:
 *   0 on error, -1 on failure (_no_ error code in errno)
 */
int phdr_table_get_arm_exidx(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                             ElfW(Addr) load_bias,
                             ElfW(Addr)** arm_exidx, unsigned* arm_exidx_count) {
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_ARM_EXIDX) {
      continue;
    }

    *arm_exidx = reinterpret_cast<ElfW(Addr)*>(load_bias + phdr->p_vaddr);
    *arm_exidx_count = (unsigned)(phdr->p_memsz / 8);
    return 0;
  }
  *arm_exidx = NULL;
  *arm_exidx_count = 0;
  return -1;
}
#endif



