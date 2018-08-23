#ifndef _LOADER_ADDR_H_
#define _LOADER_ADDR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#include "loader_soinfo.h"
#include "loader_phdr.h"
class loader_addr
{
public:
	loader_addr();
	~loader_addr();
	
	int  openmaps();
    void closemaps();
    unsigned int getParsePage(const char * name,int *size);
    unsigned char*   datastr(unsigned char *data,int size,const  char *str,int strsize );


    void  load_needed_phdr(unsigned char *data,int size);

    void load_needed_elfhead(unsigned char *data,Elf32_Ehdr *elf_header);
	int  load_needed_so_imag(soinfo* si);

	void load_needed_soinfo(soinfo* si ,unsigned char *data,int size);
	void load_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias,
                                    ElfW(Dyn)** dynamic, size_t* dynamic_count, ElfW(Word)* dynamic_flags);

	ElfW(Addr) relocate_infopage(soinfo* si, ElfW(Rel)* rel ,unsigned count);
	int relocate_soinfo(soinfo* si, ElfW(Rel)* rel, unsigned count, soinfo* needed);
	ElfW(Sym)* lookup_soinfo(const char* name,soinfo* needed);
	int  load_relocate(soinfo* si,soinfo *needed);

private:
	FILE *mfp;
	int mPid;

	Elf32_Ehdr	mElf_Header;
	int 		mPhdr_num;
	Elf32_Phdr  *phdr_table_;
	Elf32_Phdr  phdr_dynamic;
	Elf32_Addr  load_base;

	ElfW(Addr)  relocate_minaddr;
	ElfW(Addr)  relocate_maxaddr; 
	
};

unsigned int  getLibAddr(unsigned int *size);

#ifdef __cplusplus
};
#endif
#endif