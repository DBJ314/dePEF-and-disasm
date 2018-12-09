#include <stdio.h>
#include <memory.h>
#include <debugging.h>

#include "disasm.h"

void useRawDump();
void usePPCDump();
void useRTOCDump();

char* usageString =\
"%s      #PEF disassembler\n"\
"%s [option...] file > output_file\n"\
"    -c section offset #mark an offset as code (both args in hex)\n"\
"    -d section offset #mark an offset as data (both args in hex)\n"\
"    -h                #print this help message\n";

struct Frag{
	char *buf;
	long maxLength;
	short numSections;
	short instSections;
};

struct PEFSectionHeader{
	int nameOffset;
	int defaultAddress;
	int totalSize;
	int unpackedSize;
	int packedSize;
	int containerOffset;
	UInt8 sectionKind;
	UInt8 shareKind;
	UInt8 alignmant;
	UInt8 reservedA;
};

struct PEFLoaderInfoHeader{
	SInt32 mainSection;
	UInt32 mainOffset;
	SInt32 initSection;
	UInt32 initOffset;
	SInt32 termSection;
	UInt32 termOffset;
	UInt32 importedLibraryCount;
	UInt32 totalImportedSymbolCount;
	UInt32 relocSectionCount;
	UInt32 relocInstrOffset;
	UInt32 loaderStringsOffset;
	UInt32 exportHashOffset;
	UInt32 exportHashTablePower;
	UInt32 exportedSymbolCount;
};

struct PEFImportedLibrary {
	int nameOffset;
	int oldImpVersion;
	int currentVersion;
	int importedSymbolCount;
	int firstImportedSymbol;
	UInt8 options;
	UInt8 reservedA;
	UInt16 reservedB;
};

struct PEFLoaderRelocationHeader {
	UInt16 sectionIndex;
	UInt16 reservedA;
	UInt32 relocCount;
	UInt32 firstRelocOffset;
};

struct PEFExportedSymbol{
	UInt32 classAndName;
	UInt32 symbolValue;
	SInt16 sectionIndex;
};

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

int decodeFragHdr();

int processSectionHeaders();

int decodePEFSectionHdr(struct PEFSectionHeader* PEFHdr,int sectionNumber);

void decodePIData(struct PEFSectionHeader* PEFHdr, int sectionNumber);

int decodePIArg(char* pattern, int* readPoint, int prevData);

void decodeLoader(struct PEFSectionHeader* PEFHdr, int sectionNumber);

void noteISym(int sectionNumber, int offset, char* stringList, int* importSymTbl, struct PEFImportedLibrary* PEFLibList, int numImportLibs, int importIndex);

void noteESym(int sectionNumber, int offset, FourCharCode type, char* suggestedName);

void noteRTOC(int* oldRSect, int* oldROffset, int newRSect, int newROffset);

struct PEFImportedLibrary* getSourceLib(struct PEFImportedLibrary* PEFLibList, int libCount, int symbolIndex);

int getI(int i);

int* getO(int i);

short getS(int i);