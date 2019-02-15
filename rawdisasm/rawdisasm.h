#include <stdio.h>
#include <memory.h>
#include <debugging.h>

#include "disasm.h"

void useRawDump();
void usePPCDump();

char* usageString =\
"%s      #binary disassembler\n"\
"#%s [option...] file > output_file\n"\
"    -c section offset  #mark an offset as code (both args in hex)\n"\
"    -d section offset  #mark an offset as data (both args in hex)\n"\
"    -h                 #print this help message\n";

struct UserReference{
	struct UserReference* next;
	int sectionNumber;
	int offset;
	int isCode;//0 means data, 1 means code
};

struct UserReference* firstUR = 0;

int main(int argc, char *argv[]);

void noteUserRef(int sectionNumber, int offset, int isCode);

void processUserRefs();

void noteESym(int sectionNumber, int offset, FourCharCode type, char* suggestedName);

char* buf;
int size;