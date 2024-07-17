make:
	nasm -f win64 loader\alignstack.asm -o loader\alignstack.o
	x86_64-w64-mingw32-gcc loader\loader.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o loader\loader.o -Wl,-Tloader\linker.ld,--no-seh
	ld.exe -s loader\alignstack.o loader\loader.o -o loader\loader.exe
	cargo build -p toinject
	cargo build -p toinject --release
	cargo build
	cargo build --release
clean:
	del /q /f loader\*.o loader\*.exe loader\*.bin
	del /q /f target\debug\*.d target\debug\*.dll target\debug\*.exe target\debug\*.exp target\debug\*.lib target\debug\*.pdb target\debug\*.rlib
	del /q /f target\release\*.d target\release\*.dll target\release\*.exe target\release\*.exp target\release\*.lib target\release\*.pdb target\release\*.rlib
