make:
	nasm -f win64 alignstack.asm -o alignstack.o
	x86_64-w64-mingw32-gcc loader.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o loader.o -Wl,-Tlinker.ld,--no-seh
	ld.exe -s alignstack.o loader.o -o loader.exe
