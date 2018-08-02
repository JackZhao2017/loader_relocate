#ifndef _LOADER_PHDR_H_
#define _LOADER_PHDR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <elf.h>
#include <link.h>


class loader_phdr
{
public:
	loader_phdr(int fd);
	~loader_phdr();

  	size_t phdr_count() { return phdr_num_; }
  	Elf32_Addr load_start() { return reinterpret_cast<Elf32_Addr>(load_start_); }
  	size_t load_size() { return load_size_; }
  	Elf32_Addr load_bias() { return load_bias_; }
  	const Elf32_Phdr* loaded_phdr() { return loaded_phdr_; }

	bool load();
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