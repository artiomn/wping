DEFINES= 
BUILD_SUFFIX=.exe

#options if you have a bind>=4.9.4 libresolv (or, maybe, glibc)
LDLIBS=-lws2_32 -lwsock32
ADDLIB=

CC=i586-mingw32msvc-cc
CCOPT=-D_GNU_SOURCE -O2 -Wstrict-prototypes -Wall -g

wping.exe: wping.c wping.h
	$(CC) wping.c $(LDLIBS) -o wping.exe

clean:
	@rm -f *.o
	@rm -f *.exe

