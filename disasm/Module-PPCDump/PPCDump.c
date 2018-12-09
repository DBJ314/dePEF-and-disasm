#include "disasm.h"
/* primary disasm module for PowerPC */

#define kMyModName 0x70777063
/* "pwpc" */

void usePPCDump();

void mAnalyze(int sectionNumber, int size);
int mAnalysisDone(int sectionNumber, int size);
OSStatus mPrintSection(FILE* printLoc, int sectionNumber, int size);
OSStatus mPrintObjectData(FILE* printLoc, int sectionNumber, int offset, int endOffset);

void printLinkedBranch(FILE* printLoc, struct Section* curS, struct Object* curObj, int value, struct Link_Record* linkDr);

OSStatus mMergeSectionInfo(FourCharCode key, struct DataRecord* dr, void* newValue, int newVS);
OSStatus mMergeObjectInfo(FourCharCode key, struct DataRecord* dr, void* newValue, int newVS);
OSStatus mPrintSectionDR(FILE* printLoc, struct DataRecord* dr);
OSStatus mPrintObjectDR(FILE* printLoc, struct DataRecord* dr);

OSStatus ProcessTVec(int sectionNumber, int offset, void* objData, struct TVec_Record* record);
OSStatus ProcessISym(int sectionNumber, int offset, void* objData, struct ISym_Record* record);

void printkLink(FILE* printLoc, struct Link_Record* link);
void printkLnkD(FILE* printLoc, struct Link_Record* link);

void analyzeObject(struct Section* curS, struct Object* curObj);
int analyzeLocation(struct Section* curS, struct Object* curObj, int offset, int value);

void lazyBranchRef(int targetSectionNumber, int targetOffset, int pointingSectionNumber, int pointingOffset, int called);

void printInstruction(FILE* printLoc, struct Section* curS, struct Object* curObj, int value, struct Link_Record* linkDr);
void printCondBranch(FILE* printLoc, int value, char* subpartName, int hasAbs, char* destName);
void printIntegerXOInstruction(FILE* printLoc, int value, char* opName);
void printSpecialIntegerXOInstruction(FILE* printLoc, int value, char* opName, int hasRB);
void printLogicalXOInstruction(FILE* printLoc, int value, char* opName);
void printSpecialLogicalXOInstruction(FILE* printLoc, int value, char* opName, int hasRB);
void printMemInstr(FILE* printLoc, int value, char* opName, int hasXpostfix, struct Link_Record* linkDr);
void printMTSPR(FILE* printLoc, int value);
void printMFSPR(FILE* printLoc, int value);

char* getRName(int regNum);

#define printDVal(val) (val&0x8000)?'-':' ', (val&0x8000)?-val: val

struct  DisasmModule PPCDump = { 0 , kMyModName , &mAnalyze, &mAnalysisDone, &mPrintSection, &mPrintObjectData, &mMergeSectionInfo, &mMergeObjectInfo, &mPrintSectionDR, &mPrintObjectDR};

/*call this function to link to the module*/
void usePPCDump(){
	registerDisasmModule(&PPCDump);
}

void mAnalyze(int sectionNumber, int size){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct DataRecord* stampDR;
	int done = 0;
	if(curS == 0){
		fprintf(stderr, "PPCDump->mAnalyze() called on nonexistant section\n");
		return;
	}
	curObj = curS->objectLL;
	if(curObj == 0){
		return;
	}
	while(!done){
		done = 1;
		curObj = curS->objectLL;
		while(curObj!=0){
			hintO(curObj);
			stampDR = lookupObjectDataRecord(sectionNumber, curObj->offset, kMyModName);
			if((stampDR == 0)||((int*)stampDR->value)[0] < curObj->numUpdates){
				done = 0;
				markObjectAsProcessed(sectionNumber, curObj->offset, kMyModName);
				if(!isModuleBanned(curS->number, curObj->offset, kMyModName)){
					analyzeObject(curS, curObj);
				}
			}
			curObj = curObj->next;
		}
	}
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
	struct RWX_Record* rwxR;
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
	rwxR = lookupObjectDRVal(sectionNumber, offset, kRWX);
	if(rwxR==0||(rwxR->called==0&&rwxR->branched==0)){
		return -6;
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
		//printLinkedBranch(printLoc, curS, curObj, getSectVal(sectionNumber, offset), linkDr);
		//printOffset = offset+4;
		switch(linkDr->type){
			case kLinkUnknown:
			case kLinkPtr:
				fprintf(printLoc, "    DC.L %s\n", getName(linkDr->sectionNumber, linkDr->offset));
				printOffset = offset+4;
				break;
			case kLinkRRel:
			case kLinkCode:
			default:
				printInstruction(printLoc, curS, curObj, getSectVal(sectionNumber, printOffset), linkDr);
				printOffset+=4;
				break;
		}
	}
	while(printOffset+3<=endOffset){
		printInstruction(printLoc, curS, curObj, getSectVal(sectionNumber, printOffset), 0);
		printOffset+=4;
	}
	if(printOffset==endOffset){
		return 0;
	}
	printRaw(printLoc, curS->content, printOffset, endOffset);
	return 0;
}

void printLinkedBranch(FILE* printLoc, struct Section* curS, struct Object* curObj, int value, struct Link_Record* linkDr){
	if(linkDr->type == kLinkUnknown || linkDr->type == kLinkPtr){
		fprintf(printLoc, "    DC.L %s\n", getName(linkDr->sectionNumber, linkDr->offset));
		return;
	}
	if(linkDr->type == kLinkRRel){
		fprintf(printLoc, "    DC.L 0x%08x; kLinkRRel not implemented yet\n", value);
		return;
	}
	if(linkDr->type == kLinkCode){
		if((value&0xFC000000)==0x48000000){
			fprintf(printLoc, "    b%c%c %s\n", (value&1)?'l':' ', (value&2)?'a':' ', getName(linkDr->sectionNumber, linkDr->offset));
			return;
		}else if((value&0xFC000000)==0x40000000){
			printCondBranch(printLoc, value, "", 1, getName(linkDr->sectionNumber, linkDr->offset));
			//fprintf(printLoc, "    bc%c%c %d,%d,%s\n", (value&1)?'l':' ', (value&2)?'a':' ', (value>>21)&0x1F, (value>>16)&0x1F, getName(linkDr->sectionNumber, linkDr->offset));
			return;
		}else{
			fprintf(printLoc, "    DC.L 0x%08x; unknown branch opcode\n", value);
			return;
		}
	}
	fprintf(printLoc, "    DC.L 0x%08x; unknown link type\n", value);
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
			printkLink(printLoc, (struct Link_Record*)dr->value);
			break;
		case kLnkD:
			printkLnkD(printLoc, (struct Link_Record*)dr->value);
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

void analyzeObject(struct Section* curS, struct Object* curObj){
	struct DataRecord* curDR;
	struct RWX_Record*  RWr;
	struct Link_Record* Linkr;
	int curOffset = curObj->offset;
	int maxOffset = getObjectEnd(curObj);
	RWr = (struct RWX_Record* )lookupObjectDRVal(curS->number, curObj->offset, kRWX );
	Linkr = (struct Link_Record*) lookupObjectDRVal(curS->number, curObj->offset, kLink);
	if(!RWr){
		return;
	}
	if(RWr->called==0&&RWr->branched==0){
		return;
	}
	if(Linkr){
		if(Linkr->type == kLinkUnknown || Linkr->type == kLinkPtr){
			curOffset +=4;
		}
	}
	if(!isModuleBanned(curS->number, curObj->offset, 0x64632e6c /* dc.l */)){
		banModuleFromObject(curS->number, curObj->offset, 0x64632e6c /* dc.l */);
	}
	while(curOffset+3<=maxOffset){
		if(analyzeLocation(curS, curObj, curOffset, getSectVal(curS->number, curOffset))){
			maxOffset = getObjectEnd(curObj);//if something interesting happened, recalc the object end
		}
		curOffset+=4;
	}
}

/* returns true if the object might have been shortened */
int analyzeLocation(struct Section* curS, struct Object* curObj, int offset, int value){
	int isBranch = 0;
	int branchDest;
	int absAddress;
	int linking;
	int alwaysBranch;
	int destKnown;
	int returnVal = 0;
	if((value&0xFC000000)==0x48000000){
		//fprintf(stderr, "I branch 0x%08x found at (%d 0x%08x)\n", value, curS->number, offset);
		isBranch = 1;
		branchDest = (value)&0x3FFFFFC;
		if(branchDest&0x2000000){
			branchDest|=0xFC000000;
		}
		absAddress = (value>>1)&1;
		linking = value&1;
		alwaysBranch = 1;
		destKnown = 1;
	}else if((value&0xFC000000)==0x40000000){
		//fprintf(stderr, "B branch 0x%08x found at (%d 0x%08x)\n", value, curS->number, offset);
		isBranch = 1;
		branchDest = (value)&0xFFFC;
		if(branchDest&0x8000){
			branchDest|=0xFFFF0000;
		}
		absAddress = (value>>1)&1;
		linking = value&1;
		alwaysBranch = (((value>>21)&20)==20);
		destKnown = 1;
	}else if((value&0xFC0007FE)==0x4C000020){
		//fprintf(stderr, "XL bclr 0x%08x found at (%d 0x%08x)\n", value, curS->number, offset);
		isBranch = 1;
		destKnown = 0;
		absAddress = 0;
		linking = value&1;
		alwaysBranch = (((value>>21)&20)==20);
	}else if((value&0xFC0007FE)==0x4C000420){
		//fprintf(stderr, "XL bcctr 0x%08x found at (%d 0x%08x)\n", value, curS->number, offset);
		isBranch = 1;
		destKnown = 0;
		absAddress = 0;
		linking = value&1;
		alwaysBranch = (((value>>21)&20)==20);
	}
	if(!isBranch){
		return 0;
	}
	if(alwaysBranch && !linking){
		noteOffset(curS->number, offset+4, 0);
		returnVal = 1;
	}
	if(absAddress){
		fprintf(stderr, "currently unable to handle absolute branch destinations\n");
		return returnVal;
	}
	if(!destKnown){
		return returnVal;
	}
	branchDest += offset;
	if(offset<0 || offset >= curS->size){
		fprintf(stderr, "branch offset out of range of section\n");
		return returnVal;
	}
	lazyBranchRef(curS->number, branchDest, curS->number, offset, linking);
	return 1;
}

void lazyBranchRef(int targetSectionNumber, int targetOffset, int pointingSectionNumber, int pointingOffset, int called){
	struct Link_Record* curLink = lookupObjectDRVal(targetSectionNumber, targetOffset, kLnkD);
	struct RWX_Record curRWX;
	//fprintf(stderr, "potential link (%d 0x%08x)->(%d 0x%08x)\n", pointingSectionNumber, pointingOffset, targetSectionNumber, targetOffset);
	//return;
	if(curLink){
		while(curLink){
			if(curLink->sectionNumber == pointingSectionNumber && curLink->offset == pointingOffset){
				return;
			}
			curLink = curLink->next;
		}
	}
	crossReference(targetSectionNumber, targetOffset, pointingSectionNumber, pointingOffset, kLinkCode, 0);
	curRWX.read = 0;
	curRWX.written = 0;
	if(called){
		curRWX.called = 1;
		curRWX.branched = 0;
	}else{
		curRWX.branched = 1;
		curRWX.called = 0;
	}
	addObjectInfo(targetSectionNumber, targetOffset, kRWX, &curRWX, sizeof(struct RWX_Record));
	curRWX.branched = 1;
	curRWX.called = 0;
	addObjectInfo(pointingSectionNumber, pointingOffset, kRWX, &curRWX, sizeof(struct RWX_Record));
}


void printInstruction(FILE* printLoc, struct Section* curS, struct Object* curObj, int value, struct Link_Record* linkDr){
	int primOpcode = (value>>26)&0x3F;
	int success = 0;
	int xop = (value&0x7FE);
	switch(primOpcode){
		case 3://twi
			success = 1;
			fprintf(printLoc, "    twi %d,%s,%c0x%04x\n", (value>>21)&0x1F, getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			break;
		case 7://mulli
			success = 1;
			fprintf(printLoc, "    mulli %s,%s,%c0x%04x\n", getRName((value>>21)&0x1F), getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			break;
		case 8://subfic
			success = 1;
			fprintf(printLoc, "    subfic %s,%s,%c0x%04x\n", getRName((value>>21)&0x1F), getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			break;
		case 10://cmpli
			success = 1;
			if(value&0x200000){
				fprintf(printLoc, "    cmpli %d,1,%s,%c0x%04x\n", (value>>23)&0x7, getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			}else{
				fprintf(printLoc, "    cmplwi %d,%s,%c0x%04x\n", (value>>23)&0x7, getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			}
			break;
		case 11://cmpi
			success = 1;
			if(value&0x200000){
				fprintf(printLoc, "    cmpi %d,1,%s,%c0x%04x\n", (value>>23)&0x7, getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			}else{
				fprintf(printLoc, "    cmpwi %d,%s,%c0x%04x\n", (value>>23)&0x7, getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			}
			break;
		case 12://addic
			success = 1;
			fprintf(printLoc, "    addic %s,%s,%c0x%04x\n", getRName((value>>21)&0x1F), getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			break;
		case 13://addic.
			success = 1;
			fprintf(printLoc, "    addi %s,%s,%c0x%04x\n", getRName((value>>21)&0x1F), getRName((value>>16)&0x1F), printDVal(value&0xFFFF));
			break;
		case 14://addi
			success = 1;
			if(linkDr&&linkDr->type==kLinkRRel){
				fprintf(printLoc, "    addi %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getName(linkDr->sectionNumber, linkDr->offset));
			}else{
				fprintf(printLoc, "    addi %s,%s,%c0x%04x\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", printDVal(value&0xFFFF));
			}	
			break;
		case 15://addis
			success = 1;
			fprintf(printLoc, "    addis %s,%s,%c0x%04x\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", printDVal(value&0xFFFF));
			break;
		case 16://bc
			if(linkDr&&linkDr->type==kLinkCode){
				success = 1;
				printCondBranch(printLoc, value, "", 1, getName(linkDr->sectionNumber, linkDr->offset));
			}
			break;
		case 17://sc
			success = 1;
			fprintf(printLoc, "    sc\n");
			break;
		case 18://b
			if(linkDr&&linkDr->type==kLinkCode){
				success = 1;
				fprintf(printLoc, "    b%c%c %s\n", (value&1)?'l':' ', (value&2)?'a':' ', getName(linkDr->sectionNumber, linkDr->offset));
			}
			break;
		case 19://bclr[l] or bcctr[l]
			if(xop==0x020){
				success = 1;
				printCondBranch(printLoc, value, "lr", 0, 0);
				//fprintf(printLoc, "    bclr%c %d,%d,%d\n", (value&1)?'l': ' ', (value>>21)&0x1F, (value>>16)&0x1F, (value&0x1000)!=0);
			}else if(xop==0x420){
				success  = 1;
				printCondBranch(printLoc, value, "ctr", 0, 0);
				//fprintf(printLoc, "    bcctr%c %d,%d,%d\n", (value&1)?'l': ' ', (value>>21)&0x1F, (value>>16)&0x1F, (value&0x1000)!=0);
			}
			break;
		case 20://rlwimi
			success = 1;
			fprintf(printLoc, "    rlwimi%s %s,%s,%d,%d,%d\n", (value&1)?".":"", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), (value>>11)&0x1F, (value>>6)&0x1F, (value>>1)&0x1F);
			break;
		case 21://rlwinm
			success = 1;
			fprintf(printLoc, "    rlwinm%s %s,%s,%d,%d,%d\n", (value&1)?".":"", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), (value>>11)&0x1F, (value>>6)&0x1F, (value>>1)&0x1F);
			break;
		case 23://rlwnm
			success = 1;
			fprintf(printLoc, "    rlwnm%s %s,%s,%s,%d,%d\n", (value&1)?".":"", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), getRName((value>>11)&0x1F), (value>>6)&0x1F, (value>>1)&0x1F);
			break;
		case 24://ori
			success = 1;
			fprintf(printLoc, "    ori %s,%s,0x%04x\n", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), value&0xFFFF);
			break;
		case 25://oris
			success = 1;
			fprintf(printLoc, "    oris %s,%s,0x%04x\n", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), value&0xFFFF);
			break;
		case 26://xori
			success = 1;
			fprintf(printLoc, "    xori %s,%s,0x%04x\n", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), value&0xFFFF);
			break;
		case 27://xoris
			success = 1;
			fprintf(printLoc, "    xoris %s,%s,0x%04x\n", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), value&0xFFFF);
			break;
		case 28://andi.
			success = 1;
			fprintf(printLoc, "    andi. %s,%s,0x%04x\n", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), value&0xFFFF);
			break;
		case 29://andis.
			success = 1;
			fprintf(printLoc, "    andis. %s,%s,0x%04x\n", getRName((value>>21)&0x1F), getRName((value>>16)&0x1F), value&0xFFFF);
			break;
		case 31:
			switch(xop){
				case 0x00:
					success = 1;
					if(value&0x200000){
						fprintf(printLoc, "    cmp %d,1,%s,%s\n", (value>>23)&0x7, getRName((value>>16)&0x1F), getRName((value>>11)&0x1F));
					}else{
						fprintf(printLoc, "    cmpw %d,%s,%s\n", (value>>23)&0x7, getRName((value>>16)&0x1F), getRName((value>>11)&0x1F));
					}
					break;
				case 0x08:
					success = 1;
					fprintf(printLoc, "    tw %d,%s,%s", (value>>21)&0x1F, getRName((value>>16)&0x1F), getRName((value>>11)&0x1F));
					break;
				case 0x10:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "subfc");
					break;
				case 0x14:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "addc");
					break;
				case 0x16:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "mullhwu");
					break;
				case 0x26:
					success = 1;
					fprintf(printLoc, "    mfcr %s\n", getRName((value>>21)&0x1F));
					break;
				case 0x2E:
					success = 1;
					printMemInstr(printLoc, value, "lwzx", 1, linkDr);
					//fprintf(printLoc, "    lwzx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x30:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "slw");
					break;
				case 0x34:
					success = 1;
					printSpecialLogicalXOInstruction(printLoc, value, "cntlzw", 0);
					break;
				case 0x38:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "and");
					break;
				case 0x40:
					success = 1;
					if(value&0x200000){
						fprintf(printLoc, "    cmpl %d,1,%s,%s\n", (value>>23)&0x7, getRName((value>>16)&0x1F), getRName((value>>11)&0x1F));
					}else{
						fprintf(printLoc, "    cmplw %d,%s,%s\n", (value>>23)&0x7, getRName((value>>16)&0x1F), getRName((value>>11)&0x1F));
					}
					break;
				case 0x50:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "subf");
					break;
				case 0x6E:
					success = 1;
					printMemInstr(printLoc, value, "lwzux", 1, linkDr);
					//fprintf(printLoc, "    lwzux %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x78:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "andc");
					break;
				case 0x96:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "mullhw");
					break;
				case 0xAE:
					success = 1;
					printMemInstr(printLoc, value, "lbzx", 1, linkDr);
					//fprintf(printLoc, "    lbzx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0xD0:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "neg", 0);
					break;
				case 0xEE:
					success = 1;
					printMemInstr(printLoc, value, "lbzux", 1, linkDr);
					//fprintf(printLoc, "    lbzux %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0xF8:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "nor");
					break;
				case 0x110:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "subfe");
					break;
				case 0x114:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "adde");
					break;
				case 0x120:
					success = 1;
					if((value&0xFF000)==0xFF000){
						fprintf(printLoc, "    mtcr %s\n", getRName((value>>21)&0x1F));
					}else{
						fprintf(printLoc, "    mtcrf 0x%02x,%s\n", (value>>12)&0xFF, getRName((value>>21)&0x1F));
					}
					break;
				case 0x12E:
					success = 1;
					printMemInstr(printLoc, value, "stwx", 1, linkDr);
					//fprintf(printLoc, "    stwx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x16E:
					success = 1;
					printMemInstr(printLoc, value, "stwux", 1, linkDr);;
					//fprintf(printLoc, "    stwux %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x190:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "subfze", 0);
					break;
				case 0x194:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "addze", 0);
					break;
				case 0x1AE:
					success = 1;
					printMemInstr(printLoc, value, "stbx", 1, linkDr);
					//fprintf(printLoc, "    stbx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x1D0:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "subfme", 0);
					break;
				case 0x1D4:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "addme", 0);
					break;
				case 0x1D6:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "mullw");
					break;
				case 0x1EE:
					success = 1;
					printMemInstr(printLoc, value, "stbux", 1, linkDr);
					//fprintf(printLoc, "    stbux %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x214:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "add");
					break;
				case 0x22E:
					success = 1;
					printMemInstr(printLoc, value, "lhzx", 1, linkDr);
					//fprintf(printLoc, "    lhzx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x238:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "eqv");
					break;
				case 0x26E:
					success = 1;
					printMemInstr(printLoc, value, "lhzux", 1, linkDr);
					//fprintf(printLoc, "    lhzux %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x278:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "xor");
					break;
				case 0x2A6:
					success = 1;
					printMFSPR(printLoc, value);
					break;
				case 0x32E:
					success = 1;
					printMemInstr(printLoc, value, "sthx", 1, linkDr);
					//fprintf(printLoc, "    sthx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x338:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "orc");
					break;
				case 0x36E:
					success = 1;
					printMemInstr(printLoc, value, "sthux", 1, linkDr);
					//fprintf(printLoc, "    sthux %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x378:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "or");
					break;
				case 0x396:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "divwu");
					break;
				case 0x3A6:
					success = 1;
					printMTSPR(printLoc, value);
					break;
				case 0x3B8:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "nand");
					break;
				case 0x3D6:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "divw");
					break;
				case 0x410:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "subfco");
					break;
				case 0x414:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "addco");
					break;
				case 0x42A:
					success = 1;
					printMemInstr(printLoc, value, "lswx", 1, linkDr);
					//fprintf(printLoc, "    lswx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x42C:
					success = 1;
					printMemInstr(printLoc, value, "lwbrx", 1, linkDr);
					//fprintf(printLoc, "    lwbrx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x430:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "srw");
					break;
				case 0x450:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "subfo");
					break;
				case 0x4AA:
					success = 1;
					printMemInstr(printLoc, value, "lswi", 1, linkDr);
					//fprintf(printLoc, "    lswi %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x4D0:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "nego", 0);
					break;
				case 0x510:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "subfeo");
					break;
				case 0x514:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "addeo");
					break;
				case 0x52A:
					success = 1;
					printMemInstr(printLoc, value, "stswx", 1, linkDr);
					//fprintf(printLoc, "    stswx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x52C:
					success = 1;
					printMemInstr(printLoc, value, "lwbrx", 1, linkDr);
					//fprintf(printLoc, "    lwbrx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x590:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "subfzeo", 0);
					break;
				case 0x594:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "addzeo", 0);
					break;
				case 0x5AA:
					success = 1;
					printMemInstr(printLoc, value, "stswi", 1, linkDr);
					//fprintf(printLoc, "    stswi %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x5D0:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "subfmeo", 0);
					break;
				case 0x5D4:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "addmeo", 0);
					break;
				case 0x5D6:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "mullwo");
					break;
				case 0x614:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "addo");
					break;
				case 0x62C:
					success = 1;
					printMemInstr(printLoc, value, "lhbrx", 1, linkDr);
					//fprintf(printLoc, "    lhbrx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x630:
					success = 1;
					printLogicalXOInstruction(printLoc, value, "sraw");
					break;
				case 0x670:
					success = 1;
					fprintf(printLoc, "    srawi%s %s,%s,%d\n", (value&1)?".":"", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), (value>>11)&0x1F);
					break;
				case 0x72C:
					success = 1;
					printMemInstr(printLoc, value, "sthbrx", 1, linkDr);
					//fprintf(printLoc, "    sthbrx %s,%s,%s\n", getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
					break;
				case 0x734:
					success = 1;
					printSpecialLogicalXOInstruction(printLoc, value, "extsh", 0);
					break;
				case 0x774:
					success = 1;
					printSpecialIntegerXOInstruction(printLoc, value, "extsb", 0);
					break;
				case 0x796:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "divwuo");
					break;
				case 0x7D6:
					success = 1;
					printIntegerXOInstruction(printLoc, value, "divwo");
					break;
				default:
					break;
			}
			break;
		case 32://lwz
			success = 1;
			printMemInstr(printLoc, value, "lwz", 0, linkDr);
			//fprintf(printLoc, "    lwz %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 33://lwzu
			success = 1;
			printMemInstr(printLoc, value, "lwzu", 0, linkDr);
			//fprintf(printLoc, "    lwzu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 34://lbz
			success = 1;
			printMemInstr(printLoc, value, "lbz", 0, linkDr);
			//fprintf(printLoc, "    lbz %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 35://lbzu
			success = 1;
			printMemInstr(printLoc, value, "lbzu", 0, linkDr);
			//fprintf(printLoc, "    lbzu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 36://stw
			success = 1;
			printMemInstr(printLoc, value, "stw", 0, linkDr);
			//fprintf(printLoc, "    stw %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 37://stwu
			success = 1;
			printMemInstr(printLoc, value, "stwu", 0, linkDr);
			//fprintf(printLoc, "    stwu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 38://stb
			success = 1;
			printMemInstr(printLoc, value, "stb", 0, linkDr);
			//fprintf(printLoc, "    stb %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 39://stbu
			success = 1;
			printMemInstr(printLoc, value, "stbu", 0, linkDr);
			//fprintf(printLoc, "    stbu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 40://lhz
			success = 1;
			printMemInstr(printLoc, value, "lhz", 0, linkDr);
			//fprintf(printLoc, "    lhz %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 41://lhzu
			success = 1;
			printMemInstr(printLoc, value, "lhzu", 0, linkDr);
			//fprintf(printLoc, "    lhzu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 42://lha
			success = 1;
			printMemInstr(printLoc, value, "lha", 0, linkDr);
			//fprintf(printLoc, "    lha %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 43://lhau
			success = 1;
			printMemInstr(printLoc, value, "lhau", 0, linkDr);
			//fprintf(printLoc, "    lhau %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 44://sth
			success = 1;
			printMemInstr(printLoc, value, "sth", 0, linkDr);
			//fprintf(printLoc, "    sth %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 45://lhzu
			success = 1;
			printMemInstr(printLoc, value, "sthu", 0, linkDr);
			//fprintf(printLoc, "    sthu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 46://lmw
			success = 1;
			printMemInstr(printLoc, value, "lmw", 0, linkDr);
			//fprintf(printLoc, "    lmw %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 47://stmw
			success = 1;
			printMemInstr(printLoc, value, "stmw", 0, linkDr);
			//fprintf(printLoc, "    stmw %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		default:
			break;
	}
	if(!success){
		fprintf(printLoc, "    DC.L 0x%08x; unknown opcode\n", value);
	}
}

void printCondBranch(FILE* printLoc, int value, char* subpartName, int hasAbs, char* destName){
	//simple mnemonics
	//"b<cond><subpartName><link?><abs?><hint> <cr_val>,<dest>
	int bo = (value>>21)&0x1F;
	int bi = (value>>16)&0x1F;
	int abs = hasAbs&&(value&2)!=0;
	int link = value&1;
	int a = 0;
	int t = 0;
	int needsBI = 1;
	char* cond;
	if((bo&0x1E)==0){
		cond = "dnzf";
	}else if((bo&0x1E)==2){
		cond = "dzf";
	}else if((bo&0x1C)==4){
		cond = "f";
		a = (bo>>1)&1;
		t = (bo&1);
	}else if((bo&0x1E)==8){
		cond = "dnzt";
	}else if((bo&0x1E)==10){
		cond = "dzt";
	}else if((bo&0x1C)==12){
		cond = "t";
		a = (bo>>1)&1;
		t = (bo&1);
	}else if((bo&0x16)==16){
		cond = "dnz";
		a = (bo>>4)&1;
		t = bo&1;
		needsBI = 0;
	}else if((bo&0x16)==18){
		cond = "dz";
		a = (bo>>4)&1;
		t = bo&1;
		needsBI = 0;
	}else if((bo&0x14)==20){
		cond = "";
		needsBI = 0;
	}
	else{
		cond = "???";
	}
	fprintf(printLoc, "    b%s%s", cond, subpartName);
	if(link){
		fputc('l', printLoc);
	}
	if(abs){
		fputc('a', printLoc);
	}
	if(a){
		fputc((t)?'+':'-', printLoc);
	}
	fputc(' ', printLoc);
	if(needsBI){
		fprintf(printLoc, "%d", bi);
	}
	if(needsBI&&destName){
		fputc(',', printLoc);
	}
	if(destName){
		fprintf(printLoc, "%s", destName);
	}
	fputc('\n', printLoc);
}

void printIntegerXOInstruction(FILE* printLoc, int value, char* opName){
	fprintf(printLoc, "    %s", opName);
	if(value&1){
		fputc('.', printLoc);
	}
	fprintf(printLoc, " %s,%s,%s\n", getRName((value>>21)&0x1F), getRName((value>>16)&0x1F), getRName((value>>11)&0x1F));
}

void printSpecialIntegerXOInstruction(FILE* printLoc, int value, char* opName, int hasRB){
	fprintf(printLoc, "    %s", opName);
	if(value&1){
		fputc('.', printLoc);
	}
	fprintf(printLoc, " %s,%s", getRName((value>>21)&0x1F), getRName((value>>16)&0x1F));
	if(hasRB){
		fprintf(printLoc, ",%s", getRName((value>>11)&0x1F));
	}
	fputc('\n', printLoc);
}

void printLogicalXOInstruction(FILE* printLoc, int value, char* opName){
	fprintf(printLoc, "    %s", opName);
	if(value&1){
		fputc('.', printLoc);
	}
	fprintf(printLoc, " %s,%s,%s\n", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F), getRName((value>>11)&0x1F));
}

void printSpecialLogicalXOInstruction(FILE* printLoc, int value, char* opName, int hasRB){
	fprintf(printLoc, "    %s", opName);
	if(value&1){
		fputc('.', printLoc);
	}
	fprintf(printLoc, " %s,%s", getRName((value>>16)&0x1F), getRName((value>>21)&0x1F));
	if(hasRB){
		fprintf(printLoc, ",%s", getRName((value>>11)&0x1F));
	}
	fputc('\n', printLoc);
}

void printMemInstr(FILE* printLoc, int value, char* opName, int hasXpostfix, struct Link_Record* linkDr){
	if(hasXpostfix){
		fprintf(printLoc, "    %s %s,%s,%s\n", opName, getRName((value>>21)&0x1F), (value&0x1F0000)?getRName((value>>16)&0x1F):"0", getRName((value>>11)&0x1F));
		return;
	}
	if(linkDr&&linkDr->type==kLinkRRel){
		fprintf(printLoc, "    %s %s,%s(%s)\n", opName, getRName((value>>21)&0x1F), getName(linkDr->sectionNumber, linkDr->offset), getRName((value>>16)&0x1F));
	}else{
		fprintf(printLoc, "    %s %s,%c0x%04x(%s)\n", opName, getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
	}
	
}

void printMTSPR(FILE* printLoc, int value){
	int sprNum = ((value>>16)&0x1F)|((value>>6)&0x3E0);
	switch(sprNum){
		case 1:
			fprintf(printLoc, "    mtxer %s\n", getRName((value>>21)&0x1F));
			break;
		case 8:
			fprintf(printLoc, "    mtlr %s\n", getRName((value>>21)&0x1F));
			break;
		case 9:
			fprintf(printLoc, "    mtctr %s\n", getRName((value>>21)&0x1F));
			break;
		default:
			fprintf(printLoc, "    mtspr %d,%s\n", sprNum, getRName((value>>21)&0x1F));
	}
}

void printMFSPR(FILE* printLoc, int value){
	int sprNum = ((value>>16)&0x1F)|((value>>6)&0x3E0);
	switch(sprNum){
		case 1:
			fprintf(printLoc, "    mfxer %s\n", getRName((value>>21)&0x1F));
			break;
		case 8:
			fprintf(printLoc, "    mflr %s\n", getRName((value>>21)&0x1F));
			break;
		case 9:
			fprintf(printLoc, "    mfctr %s\n", getRName((value>>21)&0x1F));
			break;
		default:
			fprintf(printLoc, "    mfspr %s,%d\n", getRName((value>>21)&0x1F), sprNum);
	}
}
char rnames[32][5] = {"r0", "sp", "rtoc", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"};

char* getRName(int regNum){
	if(regNum<0 || regNum > 31){
		return "???";
	}
	return rnames[regNum];
}

void findLocalLblEdge(struct Section* curS, struct Object* theObj, int *lowBound, int *upBound){
	struct Object* curObj = curS->objectLL;
	struct RWX_Record* curRWX;
	struct Link_Record* curLnkD;
	struct ESym_Record* curESym;
	*lowBound = 0;
	while(curObj!=theObj){
		hintO(curObj);
		curRWX = (struct RWX_Record*)getObjectDRVal(curS->number, curObj->offset, kRWX);
		if(curRWX){
			if(curRWX->read||curRWX->written||curRWX->called){
				*lowBound = curObj->offset;
				curObj = curObj->next;
				continue;
			}
		}
		curLnkD = (struct Link_Record*)getObjectDRVal(curS->number, curObj->offset, kLnkD);
		if(curLnkD){
			while(curLnkD){
				if(curLnkD->type!=kLinkCode){
					*lowBound = curObj->offset;
					curObj = curObj->next;
					break;
				}
				curLnkD = curLnkD->next;
			}
			if(curLnkD){
				continue;
			}
		}
		curESym = (struct ESym_Record*)getObjectDRVal(curS->number, curObj->offset, kLnkD);
		if(curESym){
			*lowBound = curObj->offset;
			curObj = curObj->next;
			continue;
		}
		curObj = curObj->next;
	}
	
	curObj = theObj->next;
	*upBound = curS->size-1;
	while(curObj){
		hintO(curObj);
		curObj = curObj->next;
	}
}