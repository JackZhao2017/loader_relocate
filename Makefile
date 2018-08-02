# CROSS_COMPILE=arm-linux-gnueabihf-
OBJDIR = .
SRCDIR = .
VERSION = 0.0.3
AS		= $(CROSS_COMPILE)as
LD		= $(CROSS_COMPILE)ld
CC		= $(CROSS_COMPILE)gcc
CPLUS	= $(CROSS_COMPILE)g++
CPP		= $(CC) -E
AR		= $(CROSS_COMPILE)ar
NM		= $(CROSS_COMPILE)nm
STRIP	= $(CROSS_COMPILE)strip
OBJCOPY	= $(CROSS_COMPILE)objcopy
OBJDUMP	= $(CROSS_COMPILE)objdump
RM		= rm -f
MAKEDIR	= mkdir -p

CFLAGS := -lpthread -fPIC -O3 -march=armv7-a -mcpu=cortex-a9 -mfloat-abi=hard -mfpu=neon -ftree-vectorize -ffast-math -g 

CINC :=-I$(OBJDIR)

loader.out:loader.cpp loader_phdr.cpp loader_soinfo.cpp  linker_allocator.cpp
	${CC} ${CINC} -g $^ -o $@
	

clean:
	rm   loader.out
