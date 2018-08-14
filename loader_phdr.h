#ifndef _LOADER_PHDR_H_
#define _LOADER_PHDR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <elf.h>
#include <link.h>


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

class loader_phdr
{
public:
	loader_phdr();
	~loader_phdr();

  	size_t phdr_count() { return phdr_num_; }
  	Elf32_Addr load_start() { return reinterpret_cast<Elf32_Addr>(load_start_); }
  	size_t load_size() { return load_size_; }
  	Elf32_Addr load_bias() { return load_bias_; }
  	const Elf32_Phdr* loaded_phdr() { return loaded_phdr_; }

	bool load(int fd);
private:
	bool ReadElfHeader();
	bool VerifyElfHeader();
	bool ReadProgramHeader();
	bool ReserveAddressSpace();
	bool loadSegments();
	bool FindPhdr();
	bool CheckPhdr(Elf32_Addr loaded);
private:
	Elf32_Addr  mbase;
	Elf32_Ehdr	elf_header;
	int 		phdr_num_;
	int 		mfd;
	int 		phdr_size_;
	int 		load_size_;
	void* phdr_mmap_;
	Elf32_Phdr *phdr_table_;
	void* load_start_;
	Elf32_Addr load_bias_;
	const Elf32_Phdr *loaded_phdr_;
	
};


void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias,
                                    ElfW(Dyn)** dynamic, size_t* dynamic_count, ElfW(Word)* dynamic_flags);

#if defined(__arm__)
int phdr_table_get_arm_exidx(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias,
                             ElfW(Addr)** arm_exidx, unsigned* arm_exidix_count);
#endif

#ifdef __cplusplus
};
#endif

#endif