# Needs mingw-w64 (brew install mingw-w64).
msagent.exe: msagent.c
	x86_64-w64-mingw32-gcc -O2 -Wall -static -o $@ $< -lws2_32 -lpsapi

clean:
	rm -f msagent.exe
