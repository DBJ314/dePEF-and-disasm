#include "disasm.h"
/* RTOC reference decoder for PowerPC */

#define kMyModName 0x52544F43
/* "RTOC" */

void useRTOCDump();

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

void analyzeObject(struct Section* curS, struct Object* curObj);
int analyzeLocation(struct Section* curS, struct Object* curObj, int offset, int value);

void lazyBranchRef(int targetSectionNumber, int targetOffset, int pointingSectionNumber, int pointingOffset, int called);

void printInstruction(FILE* printLoc, struct Section* curS, struct Object* curObj, int value);

char* getRName(int regNum);

#define printDVal(val) (val&0x8000)?'-':' ', (val&0x8000)?-val: val

struct  DisasmModule RTOCDump = { 0 , kMyModName , &mAnalyze, &mAnalysisDone, &mPrintSection, &mPrintObjectData, &mMergeSectionInfo, &mMergeObjectInfo, &mPrintSectionDR, &mPrintObjectDR};

/*call this function to link to the module*/
void useRTOCDump(){
	registerDisasmModule(&RTOCDump);
}

void mAnalyze(int sectionNumber, int size){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct DataRecord* stampDR;
	int done = 0;
	if(curS == 0){
		fprintf(stderr, "RTOCDump->mAnalyze() called on nonexistant section\n");
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
	hintO(curObj);
	rwxR = lookupObjectDRVal(sectionNumber, offset, kRWX);
	if(rwxR==0||(rwxR->called==0&&rwxR->branched==0)){
		return -6;
	}
	if(!isModuleBanned(sectionNumber, offset, 0x70777063 /* 'pwpc' */)){
		return -7;
	}
	lnkDr = (struct Link_Record*)lookupObjectDRVal(sectionNumber, offset, kLnkD);
	linkDr = (struct Link_Record*)lookupObjectDRVal(sectionNumber, offset, kLink);
	esymR = (struct ESym_Record*)lookupObjectDRVal(sectionNumber, offset, kESym);
	fprintf(printLoc, ";glue code for '%s'\n", &(curObj->name));
	fprintf(printLoc, "    ;lwz r12, %s(rtoc)\n    ;stw rtoc, 0x0014(sp)\n    ;lwz r0, 0x0000(r12)\n    ;lwz rtoc, 0x0004(r12)\n    ;mtctr r0\n    ;bctr\n", &(curObj->name));
	printOffset+=24;
	if(printOffset==endOffset){
		return 0;
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
	if(!isModuleBanned(curS->number, curObj->offset, 0x64632E6C /* dc.l */)){
		banModuleFromObject(curS->number, curObj->offset, 0x64632E6C /* dc.l */);
	}
	if(isModuleBanned(curS->number, curObj->offset, 0x70777063 /* 'pwpc' */)){
		return;
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
	struct  RTOC_Record* RTr = lookupSectionDRVal(curS->number, kRTOC);
	struct Link_Record* curLink;
	int offsetFromRTOC;
	int offsetFromRSect;
	int primOpcode = (value>>26)&0x3F;
	struct RWX_Record curRWX = { 0, 0, 0, 1};//branched = 1, all others 0
	if(!((primOpcode>=32 && primOpcode <=44)||primOpcode == 14)){
		return 0;
	}
	if((value&0x001F0000)!=0x00020000){
		return 0;
	}
	if(RTr==0){
		return 0;
	}
	offsetFromRTOC = value&0x0000FFFF;
	if(value&0x8000){
		offsetFromRTOC|=0xFFFF0000;//sign-extend it
	}
	offsetFromRSect = RTr->offset+offsetFromRTOC;
	curLink = lookupObjectDRVal(RTr->sectionNumber, offsetFromRSect, kLnkD);
	if(curLink){//make sure it only makes this link once
		while(curLink){
			if(curLink->sectionNumber == curS->number && curLink->offset == offset){
				return 0;
			}
			curLink = curLink->next;
		}
	}
	noteOffset(curS->number, offset, 0);
	crossReference(RTr->sectionNumber, offsetFromRSect, curS->number, offset, kLinkRRel, 0);
	if(offset!=curObj->offset){
		addObjectInfo(curS->number, offset, kRWX, &curRWX, sizeof(struct RWX_Record));
	}
	/* match for glue pattern
	 *	lwz r12, 0xXXXX(rtoc)
	 *	stw rtoc, 0x0014(sp)
	 *	lwz r0, 0x0000(r12)
	 *	lwz rtoc, 0x0004(r12)
	 *	mtctr r0
	 *	bctr
	 */
	if((value&0xFFFF0000)==0x81820000&&(offset+23)<=getObjectEnd(curObj)){
		if(getSectVal(curS->number, offset+0x04)==0x90410014 &&\
		   getSectVal(curS->number, offset+0x08)==0x800C0000 &&\
		   getSectVal(curS->number, offset+0x0C)==0x804C0004 &&\
		   getSectVal(curS->number, offset+0x10)==0x7C0903A6 &&\
		   getSectVal(curS->number, offset+0x14)==0x4E800420){
		   	if(offset+24<=getObjectEnd(curObj)){
				noteOffset(curS->number, offset+24, 0);
			}
			banModuleFromObject(curS->number, offset, 0x70777063 /* 'pwpc' */);
			setObjectName(curS->number, offset, getName(RTr->sectionNumber, offsetFromRSect));
		}
	}
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


void printInstruction(FILE* printLoc, struct Section* curS, struct Object* curObj, int value){
	int primOpcode = (value>>26)&0x3F;
	int success = 0;
	int xop = (value&0x7FE);
	switch(primOpcode){
		case 32://lwz
			success = 1;
			fprintf(printLoc, "    lwz %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 33://lwzu
			success = 1;
			fprintf(printLoc, "    lwzu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 34://lbz
			success = 1;
			fprintf(printLoc, "    lbz %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 35://lbzu
			success = 1;
			fprintf(printLoc, "    lbzu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 36://stw
			success = 1;
			fprintf(printLoc, "    stw %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 37://stwu
			success = 1;
			fprintf(printLoc, "    stwu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 38://stb
			success = 1;
			fprintf(printLoc, "    stb %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 39://stbu
			success = 1;
			fprintf(printLoc, "    stbu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 40://lhz
			success = 1;
			fprintf(printLoc, "    lhz %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 41://lhzu
			success = 1;
			fprintf(printLoc, "    lhzu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 42://lha
			success = 1;
			fprintf(printLoc, "    lha %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 43://lhau
			success = 1;
			fprintf(printLoc, "    lhau %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 44://sth
			success = 1;
			fprintf(printLoc, "    sth %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 45://lhzu
			success = 1;
			fprintf(printLoc, "    sthu %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 46://lmw
			success = 1;
			fprintf(printLoc, "    lmw %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		case 47://stmw
			success = 1;
			fprintf(printLoc, "    stmw %s,%c0x%04x(%s)\n", getRName((value>>21)&0x1F), printDVal(value&0xFFFF), getRName((value>>16)&0x1F));
			break;
		default:
			break;
	}
	if(!success){
		fprintf(printLoc, "    DC.L 0x%08x; unknown opcode (RTOCDump)\n", value);
	}
}

char rnames[32][5] = {"r0", "sp", "rtoc", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"};

char* getRName(int regNum){
	if(regNum<0 || regNum > 31){
		return "???";
	}
	return rnames[regNum];
}