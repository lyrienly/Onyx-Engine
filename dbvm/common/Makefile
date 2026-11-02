ASM ?= yasm
CC ?= gcc
CFLAGS = -m32 -fno-builtin-strlen -fno-builtin-strcat -fno-builtin-strcpy -fno-builtin-malloc -fno-builtin-snprintf -fno-stack-protector -fno-pie -fno-pic -mno-red-zone -g
AFLAGS = -f elf32 -gDWARF2

all:
	echo ${SERIALPORT}
	@${ASM} ${AFLAGS} commona.asm -o commona.o -DSERIALPORT=${SERIALPORT}
	@${CC} ${CFLAGS} common.c -c -o common.o -DSERIALPORT=${SERIALPORT}
	@echo "common created"

clean:
	@rm -f *.o
	@rm -f *~
	@echo "common cleaned"
