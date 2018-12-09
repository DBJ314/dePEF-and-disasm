#include "disasm.h"
/* a very boring disasm module*/

#define kMyModName 0x64632e6c
/* "dc.l" */

void useRawDump();

void mAnalyze(int sectionNumber, int size);
int mAnalysisDone(int sectionNumber, int size);
OSStatus mPrintSection(FILE* printLoc, int sectionNumber, int size);
OSStatus mPrintObjectData(FILE* printLoc, int sectionNumber, int offset, int endOffset);
OSStatus mMergeSectionInfo(FourCharCode key, struct DataRecord* dr, void* newValue, int newVS);
OSStatus mMergeObjectInfo(FourCharCode key, struct DataRecord* dr, void* newValue, int newVS);
OSStatus mPrintSectionDR(FILE* printLoc, struct DataRecord* dr);
OSStatus mPrintObjectDR(FILE* printLoc, struct DataRecord* dr);

OSStatus ProcessTVec(int sectionNumber, int offset, void* objData, struct TVec_Record* record);
OSStatus ProcessISym(int sectionNumber, int offset, void* objData, struct ISym_Record* record);

void printkLink(FILE* printLoc, struct Link_Record* link);
void printkLnkD(FILE* printLoc, struct Link_Record* link);

struct  DisasmModule RawDump = { 0 , kMyModName , &mAnalyze, &mAnalysisDone, &mPrintSection, &mPrintObjectData, &mMergeSectionInfo, &mMergeObjectInfo, &mPrintSectionDR, &mPrintObjectDR};

int Module_RawDump;

/*call this function to link to the module*/
void useRawDump(){
	registerDisasmModule(&RawDump);
}

void mAnalyze(int sectionNumber, int size){
	markSectionAsProcessed(sectionNumber, kMyModName);
	return;
}

int mAnalysisDone(int sectionNumber, int size){
	return 1;
}

OSStatus mPrintSection(FILE* printLoc, int sectionNumber, int size){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	int offset = 0;
	if(curS==0){
		fprintf(printLoc,";no section %d\n",sectionNumber);
		return 1;
	}
	curObj = curS->objectLL;
	while(offset<size){
		if(curObj==0){
			printRaw(printLoc, curS->content, offset, size-1);
			return 0;
		}
		if(curObj->offset<offset){
			curObj=curObj->next;
			continue;
		}
		if(curObj->offset==offset){
			fprintf(printLoc,"%s:\n",curObj->name);
			curObj=curObj->next;
			continue;
		}
		printRaw(printLoc, curS->content, offset, curObj->offset-1);
		offset=curObj->offset;
	}
	//no code should ever reach this point
	fprintf(stderr,"horrible mPrintSection failure\n");
	return 1;
}

OSStatus mPrintObjectData(FILE* printLoc, int sectionNumber, int offset, int endOffset){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct Link_Record* lnkDr;
	struct Link_Record* linkDr;
	struct ESym_Record* esymR;
	int printOffset = offset;
	if(isModuleBanned(sectionNumber, offset, kMyModName)){
		return -5;
	}
	if(curS==0){
		fprintf(printLoc,";no section %d\n",sectionNumber);
		return 1;
	}
	curObj=getObject(curS, offset);
	if(curObj == 0){
		return -1;
	}
	lnkDr = (struct Link_Record*)lookupObjectDRVal(sectionNumber, offset, kLnkD);
	linkDr = (struct Link_Record*)lookupObjectDRVal(sectionNumber, offset, kLink);
	esymR = (struct ESym_Record*)lookupObjectDRVal(sectionNumber, offset, kESym);
	if(esymR){
		fprintf(printLoc, "    export %s\n", &(curObj->name));
	}
	if(lnkDr||esymR){
		fprintf(printLoc,"%s:\n",curObj->name);
	}
	if(linkDr!=0){
		fprintf(printLoc, "    DC.L %s\n", getName(linkDr->sectionNumber, linkDr->offset));
		printOffset = offset+4;
	}
	printRaw(printLoc, curS->content, printOffset, endOffset);
	return 0;
}
OSStatus mMergeSectionInfo(FourCharCode key, struct DataRecord* dr, void* newValue, int newVS){
	void* copiedValue;
	switch(key){
		case kRTOC://only one RTOC allowed
		default:
			return -1;//can't merge unknown DataRecords together
	}
}
OSStatus mMergeObjectInfo(FourCharCode key, struct DataRecord* dr, void* newValue, int newVS){
	void* oldValue;
	void* copiedValue;
	switch(key){
		case kRWX:
			oldValue = dr->value;
			if(newVS!=sizeof(struct RWX_Record)){
				return -3;
			}
			((struct RWX_Record*)oldValue)->read|=((struct RWX_Record*)newValue)->read;
			((struct RWX_Record*)oldValue)->written|=((struct RWX_Record*)newValue)->written;
			((struct RWX_Record*)oldValue)->called|=((struct RWX_Record*)newValue)->called;
			((struct RWX_Record*)oldValue)->branched|=((struct RWX_Record*)newValue)->branched;
			return 0;
		case kBan:
			if(newVS!=sizeof(struct Ban_Record)){
				return -3;
			}
			copiedValue = (void*) malloc(newVS);
			if(copiedValue==0){
				return -1;
			}
			BlockMove(newValue, copiedValue, (Size)newVS);
			((struct Ban_Record*)copiedValue)->next = (struct Ban_Record*)dr->value;
			dr->value = copiedValue;
			return 0;
		case kLink:
		case kLnkD:
			if(newVS!=sizeof(struct Link_Record)){
				return -3;
			}
			copiedValue = (void*) malloc(newVS);
			if(copiedValue==0){
				return -1;
			}
			BlockMove(newValue, copiedValue, (Size)newVS);
			((struct Link_Record*)copiedValue)->next = (struct Link_Record*)dr->value;
			dr->value = copiedValue;
			return 0;
		case kTVec:
		case kISym:
		default:
			return -1;//can't merge unknown DataRecords together
	}
}

OSStatus mPrintSectionDR(FILE* printLoc, struct DataRecord* dr){
	switch(dr->key){
		case kRTOC:
			fprintf(printLoc, ";RTOC at (%d 0x%08x)\n", ((struct RTOC_Record*)dr->value)->sectionNumber, ((struct RTOC_Record*)dr->value)->offset);
			break;
		default:
			return -1;
	}
	return 0;
}
OSStatus mPrintObjectDR(FILE* printLoc, struct DataRecord* dr){
	switch(dr->key){
		case kRWX:
			fprintf(printLoc, ";RWCB: %01x%01x%01x%01x\n", ((struct RWX_Record*)dr->value)->read, ((struct RWX_Record*)dr->value)->written, ((struct RWX_Record*)dr->value)->called, ((struct RWX_Record*)dr->value)->branched);
			break;
		case kLink:
			printkLink(printLoc, (struct Link_Record*)(dr->value));
			break;
		case kLnkD:
			printkLnkD(printLoc, (struct Link_Record*)(dr->value));
			break;
		default:
			return -1;
	}
	return 0;
}

void printkLink(FILE* printLoc, struct Link_Record* link){
	struct Section* lnkS;
	struct Object* lnkObj;
	lnkS = getSection(link->sectionNumber);
	if(!lnkS){
		fprintf(stdout, ";Link with mangled section number\n");
		if(link->next){
			printkLink(printLoc, link->next);
		}
		return;
	}
	lnkObj = getObject(lnkS, link->offset);
	if(!lnkObj){
		fprintf(stdout, ";Link with mangled object offset\n");
		if(link->next){
			printkLink(printLoc, link->next);
		}
		return;
	}
	fprintf(printLoc, ";'%c%c%c%c' Link to '%s' (%d 0x%08x)\n", (link->type>>24)&255,(link->type>>16)&255,(link->type>>8)&255,link->type&255, &(lnkObj->name), link->sectionNumber, link->offset);
	if(link->next){
			printkLink(printLoc, link->next);
	}
}

void printkLnkD(FILE* printLoc, struct Link_Record* link){
	struct Section* lnkS;
	struct Object* lnkObj;
	lnkS = getSection(link->sectionNumber);
	if(!lnkS){
		fprintf(stdout, ";Link with mangled section number\n");
		if(link->next){
			printkLnkD(printLoc, link->next);
		}
		return;
	}
	lnkObj = getObject(lnkS, link->offset);
	if(!lnkObj){
		fprintf(stdout, ";Link with mangled object offset\n");
		if(link->next){
			printkLnkD(printLoc, link->next);
		}
		return;
	}
	fprintf(printLoc, ";'%c%c%c%c' Link from '%s' (%d 0x%08x)\n", (link->type>>24)&255,(link->type>>16)&255,(link->type>>8)&255,link->type&255, &(lnkObj->name), link->sectionNumber, link->offset);
	if(link->next){
			printkLnkD(printLoc, link->next);
	}
}
