ASM ?= yasm
CC ?= gcc
LD ?= ld
OBJCOPY ?= objcopy
AFLAGS = -gDWARF2 -f elf32
CFLAGS = -m32 -O0 -g -fno-stack-protector -fno-pie -fno-pic -mno-red-zone -fcf-protection=none
LDFLAGS = -melf_i386 -static -no-pie -T kernel.lnk
EXTRA_INC = -I ../common

all:
	@${ASM} ${AFLAGS} vmloader.asm -o vmloader.o -DVMMSIZE=`stat -c%s '../vmm.bin'` -DSERIALPORT=${SERIALPORT}
	@${CC} ${CFLAGS} ${EXTRA_INC} vmloaderc.c -c -o vmloaderc.o -DSERIALPORT=${SERIALPORT} -DVMMSIZE=`stat -c%s '../vmm.bin'`
	@${LD} ${LDFLAGS} vmloader.o vmloaderc.o ../common/common.o ../common/commona.o -o ../vmloader.elf -Map ../vmloader.map
	@${OBJCOPY} -O binary ../vmloader.elf ../vmloader.bin
	@echo "vmloader created"	
	
clean:
	@rm -f *.o
	@rm -f *.bin
	@rm -f *.map
	@rm -f *.*~
	@rm -f *~
	@echo "vmloader cleaned"	
