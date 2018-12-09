#ifndef __Disasm__
#define __Disasm__

#include <memory.h>
#include <stdio.h>
#include <mactypes.h>
#include <CodeFragments.h>
#include <Debugging.h>
struct DisasmModule{
	struct DisasmModule* next;//used for linked list
	FourCharCode name;
	void (*analyze)(int sectionNumber, int size);
	int (*analysisDone)(int sectionNumber, int size);
	OSStatus (*printSection)(FILE* printLoc, int sectionNumber, int size);
	OSStatus (*printObjectData)(FILE* printLoc, int sectionNumber, int offset, int endOffset);
	OSStatus (*mergeSectionInfo)(FourCharCode key, struct DataRecord* dr, void* newValue, int newVS);
	OSStatus (*mergeObjectInfo)(FourCharCode key, struct DataRecord* dr, void* newValue, int newVS);
	OSStatus (*printSectionDR)(FILE* printLoc, struct DataRecord* dr);
	OSStatus (*printObjectDR)(FILE* printLoc, struct DataRecord* dr);
};

struct Section{
	int number;
	char* content;
	int address;
	int size;
	int numUpdates;
	int done;//flag used for optimization in disasm loop
	struct DataRecord* dataList;//data records for use of all modules
	struct Object* objectLL;
	struct Section* next;
};

struct Object{
	struct Section* parent;
	struct Object* next;
	int offset;
	int address;
	int numUpdates;
	struct DataRecord* dataList;//data records for use of all modules
	char name[256];
};

struct DataRecord{
	struct DataRecord* next;
	FourCharCode key;
	void* value;
	int valueSize;
};

OSStatus registerSection(int sectionNumber, char* contents, int length, int address);

OSStatus registerObject(int sectionNumber, int offset);

void setObjectName(int sectionNumber, int offset, char* name);

OSStatus registerDisasmModule(struct DisasmModule* newModule);

void printModules(FILE* output);

struct DisasmModule* lookupModule(FourCharCode name);

OSStatus runDisassembly();

OSStatus crossReference(int targetSectionNumber, int targetOffset, int pointingSectionNumber, int pointingOffset, FourCharCode type, char* suggestedName);

OSStatus noteOffset(int sectionNumber, int offset, char* suggestedName);

OSStatus banModuleFromObject(int sectionNumber, int offset, FourCharCode moduleName);

int isModuleBanned(int sectionNumber, int offset, FourCharCode moduleName);

struct Section* getSection(int sectionNumber);

struct Section* getSectionFromAddress(int address);

struct Object* getObject(struct Section* curS,int offset);

void hintS(struct Section* curS);

void hintO(struct Object* curObj);

int getSectVal(int sectionNumber, int offset);

int createName(int sectionNumber,int offset,char* name);

char convertToHex(int i);

char* getName(int sectionNumber,int offset);

struct DataRecord* lookupSectionDataRecord(int sectionNumber, FourCharCode key);

struct DataRecord* lookupObjectDataRecord(int sectionNumber, int offset, FourCharCode key);

void* lookupSectionDRVal(int sectionNumber, FourCharCode key);

void* lookupObjectDRVal(int sectionNumber, int offset, FourCharCode key);

OSStatus createSectionDataRecord(int sectionNumber, FourCharCode key, void* value, int valueSize);

OSStatus createObjectDataRecord(int sectionNumber, int offset, FourCharCode key, void* value, int valueSize);

OSStatus addSectionInfo(int sectionNumber, FourCharCode key, void* value, int valueSize);

OSStatus addObjectInfo(int sectionNumber, int offset, FourCharCode key, void* value, int valueSize);

void updateSection(int sectionNumber);

void updateObject(int sectionNumber, int offset);

void markSectionAsProcessed(int sectionNumber, FourCharCode module);

void markObjectAsProcessed(int sectionNumber, int offset, FourCharCode module);

int isModuleDoneWithSection(struct DisasmModule* curM, struct Section* curS);

int getObjectEnd(struct Object* curObj);

/* printing functions */
OSStatus printSection(FILE* printLoc, int sectionNumber);

OSStatus printObjectData(FILE* printLoc, int sectionNumber, int offset);

void printAllSections(FILE* printLoc);

void printSectionDR(FILE* printLoc, struct DataRecord* dr);

void printObjectDR(FILE* printLoc, struct DataRecord* dr);

void printRaw(FILE* printLoc, char* content, int startOffset, int endOffset);

void print2HexDigits(FILE* printLoc, char input);
/* global variables */

#ifdef Disasm_Engine
struct Section* firstSection;
struct DisasmModule* firstModule;

char emptyString;

struct Section* cachedSection = 0;
struct Section* hintedSection = 0;

struct Object* cachedObject = 0;
struct Object* hintedObject = 0;
#else

extern struct Section* firstSection;
extern struct DisasmModule* firstModule;

extern char emptyString;

extern struct Section* cachedSection;
extern struct Section* hintedSection;

extern struct Object* cachedObject;
extern struct Object* hintedObject;
#endif

/* Types Of Data Records */

/* Data Records only found in Sections */

/* RTOC - points to the TOC base. In all sections, for convenience */
#define kRTOC 0x52544F43
struct RTOC_Record{
	int sectionNumber;
	int offset;
};

/* Data Records only found in Objects */

/* Ban  - forbids module from looking at Object */
#define kBan 0x42616E20
struct Ban_Record{
	struct Ban_Record* next;
	FourCharCode bannedModule;
};

/* Link - catalogues outgoing references */
/* LnkD - catalogues incoming references */
#define kLink 0x4C696E6B
#define kLnkD 0x4C6E6B44
struct Link_Record{
	struct Link_Record* next;
	FourCharCode type;
	int sectionNumber;
	int offset;
};
/* link types: */

/* kLinkUnknown implies a pointer */
#define kLinkUnknown 0x3F3F3F3F
/* kLinkPtr implies DC.L */
#define kLinkPtr 0x50747220
/* kLinkRRel means base-reg relative access that points to a definite section offset */
#define kLinkRRel 0x5252656C
/* kLinkCode means it's a branch instruction */
#define kLinkCode 0x436F6465

/* RWX  - keeps track of the various ways an object is referenced */
#define kRWX 0x52575820
struct RWX_Record{
	int read;
	int written;
	int called;
	int branched;
};

/* TVec - Transition Vector to a function we are disassembling */
#define kTVec 0x54566563
struct TVec_Record{
	int sectionNumber;
	int offset;
};

/* ISym - Imported Symbol */
#define kISym 0x4953796D
struct ISym_Record{
	char* name;
	char* libName;
	FourCharCode type;/* Can be 'Code', 'Data', 'TVec', 'TOC ', or 'Glue' */
	int weak;
};
#define kCode 0x436F6465
#define kData 0x44617461
//kTVec already defined
#define kTOC 0x544F4320
#define kGlue 0x476C7565

/* ESym - Exported Symbol */
#define kESym 0x4553796D
struct ESym_Record{
	FourCharCode type;/* Can be 'Init', 'Term', 'Main', 'Code', 'Data', 'TVec', 'TOC ', or 'Glue' */
};

#define kInit 0x496E6974
#define kTerm 0x5465726D
#define kMain 0x4D61696E
//kCode already defined
//kData already defined
//kTVec already defined
//kTOC  already defined
//kGlue already defined

/* ARec - access to a record offset relative to a register*/
#define kARec 0x41526563
struct ARec_Record{
	char* offsetName; //usually looks like "Struct.Member"
};




#endif

