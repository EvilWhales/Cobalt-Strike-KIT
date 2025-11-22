CC = x86_64-w64-mingw32-gcc
STRIP = x86_64-w64-mingw32-strip
RM = rm -vf

BIN=./bin
SRC=./src

.PHONY: all clean
all: pingscanner.bof.o portscanner.bof.o

pingscanner.bof.o: $(SRC)/pingscanner.c
portscanner.bof.o: $(SRC)/portscanner.c

pingscanner.exe: $(SRC)/pingscanner.c $(SRC)/parser.c

%.bof.o : $(SRC)/%.c
	$(CC) -DBOF $(CFLAGS) $(TARGET_ARCH) -c -o $(BIN)/$@ $<

clean:
	@$(RM) $(BIN)/*.o 2>/dev/null || true
	@$(RM) $(BIN)/*.exe 2>/dev/null || true

# Need to fix imports so these can compile as exes
%.exe: $(SRC)/%.c
	$(CC) $(CFLAGS) -o $(BIN)/$@ -lws2_32 -liphlpapi $<
	#gcc -o pingscanner pingscanner.c parser.c 

	@#-lws2_32 -liphlpapi
	@#-Os -s -Qn -nostdlib -Wl,-s,--exclude-all-symbols

#portscanner:
# 	x86_64-w64-mingw32-gcc -o $(BIN)/portscanner.exe portscanner.c parser.c server-info.c -lws2_32 -liphlpapi -lnetapi32
#	$(STRIP) $(BIN)/$@

parser: 
	$(CC) -DPARSER_MAIN -o $(BIN)/parser.exe $(SRC)/parser.c -lws2_32 
	#gcc -DPARSER_MAIN -o $(BIN)/parser $(SRC)/parser.c 
