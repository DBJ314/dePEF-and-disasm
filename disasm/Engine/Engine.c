/* main API for disassembler */
#define Disasm_Engine

#include "disasm.h"

OSStatus registerSection(int sectionNumber, char* contents, int length, int address){
	struct Section* thisSection;
	thisSection = (struct Section*)malloc(sizeof(struct Section));
	if(thisSection==0){
		fprintf(stderr,"out of memory\n");
		return 1;
	}
	thisSection->number=sectionNumber;
	thisSection->content=contents;
	thisSection->size=length;
	thisSection->address=address;
	thisSection->objectLL=(struct Object*)0;
	thisSection->dataList = (struct DataRecord*)0;
	thisSection->done=false;
	thisSection->next=firstSection;
	thisSection->numUpdates = 0;
	firstSection=thisSection;
	return 0;
}

OSStatus registerObject(int sectionNumber, int offset){
	struct Section* currentSection = getSection(sectionNumber);
	struct Object* newObj;
	struct Object* temp;
	if(currentSection==0){
		fprintf(stderr,"invalid section number\n");
		return 1;
	}
	if(getObject(currentSection,offset)){
		fprintf(stderr,"object already exists\n");
		return 1;
	}
	newObj = (struct Object*)malloc(sizeof(struct Object));
	if(newObj==0){
		fprintf(stderr,"out of memory\n");
		return 1;
	}
	newObj->parent=currentSection;
	newObj->offset=offset;
	newObj->address=currentSection->address+offset;
	newObj->numUpdates = 0;
	newObj->dataList = (struct DataRecord*)0;
	createName(sectionNumber,offset,newObj->name);
	temp=currentSection->objectLL;
	updateSection(sectionNumber);
	if((temp==0)||temp->offset>offset){
		newObj->next=currentSection->objectLL;
		currentSection->objectLL=newObj;
		return 0;
	}
	
	while((temp->next!=0)&&temp->next->offset<=offset){
		temp=temp->next;
	}
	newObj->next=temp->next;
	temp->next=newObj;
	return 0;
}

void setObjectName(int sectionNumber, int offset, char* name){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	int nameLen;
	int i;
	if(curS==0){
		fprintf(stderr,"invalid section number\n");
		return;
	}
	curObj=getObject(curS,offset);
	if(curObj==0){
		fprintf(stderr,"invalid offset\n");
		return;
	}
	for(i=0;i<256;i++){
		curObj->name[i]=0;
	}
	nameLen = strlen(name);
	if(nameLen >= 250){
		fprintf(stderr, "warning name from 0x%08x truncated\n", name);
		nameLen = 249;
	}
	for(i = 0;i<nameLen;i++){
		curObj->name[i]=name[i];
	}
}

OSStatus registerDisasmModule(struct DisasmModule* newModule){
	FourCharCode newCode=newModule->name;
	struct DisasmModule* temp = firstModule;
	newModule->next=0;
	if(firstModule==0){
		firstModule=newModule;
		return 0;
	}
	while(temp->next!=0){
		if(temp->name==newCode){
			return 1;
		}
		temp=temp->next;
	}
	temp->next=newModule;
	return 0;
}

void printModules(FILE* output){
	struct DisasmModule* temp = firstModule;
	int mName;
	mName = (int)temp->name;
	while(temp!=0){
		mName = (int)temp->name;
		fprintf(output,"Module '%c%c%c%c'\n",(mName>>24)&255,(mName>>16)&255,(mName>>8)&255,mName&255);
		temp=temp->next;
	}
}

struct DisasmModule* lookupModule(FourCharCode name){
	struct DisasmModule* modj = firstModule;
	while(modj!=0){
		if(modj->name==name){
			return modj;
		}
		modj=modj->next;
	}
	return 0;
}

OSStatus crossReference(int targetSectionNumber, int targetOffset, int pointingSectionNumber, int pointingOffset, FourCharCode type, char* suggestedName){
	OSStatus err = noteOffset(targetSectionNumber, targetOffset, suggestedName);
	struct Link_Record pLink;
	struct Link_Record tLnkD;
	if(err != 0){
		return err;
	}
	err = noteOffset(pointingSectionNumber, pointingOffset, (char*) 0);
	if(err != 0){
		return err;
	}
	pLink.type = type;
	pLink.sectionNumber = targetSectionNumber;
	pLink.offset = targetOffset;
	pLink.next = 0;
	err = addObjectInfo(pointingSectionNumber, pointingOffset, kLink, &pLink, sizeof(struct Link_Record));
	if(err != 0){
		return err;
	}
	tLnkD.type = type;
	tLnkD.sectionNumber = pointingSectionNumber;
	tLnkD.offset = pointingOffset;
	tLnkD.next = 0;
	err = addObjectInfo(targetSectionNumber, targetOffset, kLnkD, &tLnkD, sizeof(struct Link_Record));
	return err;
}

OSStatus noteOffset(int sectionNumber, int offset, char* suggestedName){
	struct Section* curS = getSection(sectionNumber);
	struct Object* locObj;
	if(curS==0){
		return 1;
	}
	locObj=getObject(curS,offset);
	if(locObj==0){
		registerObject(sectionNumber, offset);
	}
	if(suggestedName!=0){
		setObjectName(sectionNumber,offset,suggestedName);
	}
	return 0;
}

OSStatus banModuleFromObject(int sectionNumber, int offset, FourCharCode moduleName){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct Ban_Record banR;
	if(curS == 0){
		return -1;
	}
	curObj = getObject(curS, offset);
	if(curObj == 0){
		return -2;
	}
	banR.next = 0;
	banR.bannedModule = moduleName;
	return addObjectInfo(sectionNumber, offset, kBan, &banR, sizeof(struct Ban_Record));
}

int isModuleBanned(int sectionNumber, int offset, FourCharCode moduleName){
	struct Ban_Record*  banR = lookupObjectDRVal(sectionNumber, offset, kBan);
	if(banR == 0){
		return 0;
	}
	while(banR!=0){
		if(banR->bannedModule == moduleName){
			return 1;
		}
		banR = banR->next;
	}
	return 0;
}

OSStatus runDisassembly(){
	struct Section* curS = firstSection;
	struct DisasmModule* curM = firstModule;
	int done = 0;
	if(firstSection==0){
		fprintf(stderr,"no sections to disassemble\n");
		return 1;
	}
	done=0;
	while(done==0){
		done = 1;
		curM = firstModule;
		while(curM!=0){
			curS = firstSection;
			while(curS!=0){
				if(isModuleDoneWithSection(curM, curS)){
					//the module is done with this section
				}else{
					curM->analyze(curS->number, curS->size);
					done = 0;
				}
				curS = curS->next;
			}
			curM = curM->next;
		}
	}
	return 0;
}

struct Section* getSection(int sectionNumber){
	struct Section* currentSection = firstSection;
	if(cachedSection&&cachedSection->number == sectionNumber){
		return cachedSection;
	}
	if(hintedSection&&hintedSection->number == sectionNumber){
		return hintedSection;
	}
	while(currentSection!=0&&(currentSection->number!=sectionNumber)){
		currentSection=currentSection->next;
	}
	if(currentSection){
		cachedSection = currentSection;
	}
	return currentSection;
}

struct Section* getSectionFromAddress(int address){
	struct Section* currentSection = firstSection;
	while(currentSection!=0&&((address<currentSection->address)||(address>=currentSection->size))){
		currentSection=currentSection->next;
	}
	return currentSection;
}

struct Object* getObject(struct Section* curS,int offset){
	struct Object* curObj;
	if(!curS){
		return 0;
	}
	if(cachedObject&&cachedObject->parent==curS&&cachedObject->offset == offset){
		return cachedObject;
	}
	if(hintedObject&&hintedObject->parent==curS&&hintedObject->offset == offset){
		return  hintedObject;
	}
	curObj = curS->objectLL;
	if(curObj == 0){
		return 0;// extra sanity check up front to discourage crashing
	}
	while((curObj!=0)&&curObj->offset<=offset){
		if(curObj->offset==offset){
			cachedObject = curObj;
			return curObj;
		}
		curObj = curObj->next;
	}
	return 0;
}

void hintS(struct Section* curS){
	hintedSection = curS;
}

void hintO(struct Object* curObj){
	hintedSection = curObj->parent;
	hintedObject = curObj;
}

int getSectVal(int sectionNumber, int offset){
	struct Section* curS = getSection(sectionNumber);
	int result = 0;
	if(curS==0){
		fprintf(stderr, "error: getSectVal() failed\n");
		return 0;
	}
	if(offset<0 || offset+3 > curS->size){
		fprintf(stderr, "error: getSectVal() index out of bounds (%d, 0x%08x)\n", sectionNumber, offset);
		return 0;
	}
	result |= ((curS->content[offset])<<24)&0xFF000000;
	result |= ((curS->content[offset+1])<<16)&0xFF0000;
	result |= ((curS->content[offset+2])<<8)&0xFF00;
	result |= ((curS->content[offset+3]))&0xFF;
	return result;
}

int createName(int sectionNumber,int offset,char* name){
	int length = 0;
	name[length++]='S';
	name[length++]='_';
	name[length++]='0';
	name[length++]='x';
	if(sectionNumber&0x00000F00){
		name[length++]=convertToHex((sectionNumber>>8)&15);
	}
	if(sectionNumber&0x00000FF0){
		name[length++]=convertToHex((sectionNumber>>4)&15);
	}
	name[length++]=convertToHex(sectionNumber&15);
	name[length++]='_';
	name[length++]='O';
	name[length++]='_';
	name[length++]='0';
	name[length++]='x';
	if(offset&0xF0000000){
		name[length++]=convertToHex((offset>>28)&15);
	}
	if(offset&0xFF000000){
		name[length++]=convertToHex((offset>>24)&15);
	}
	if(offset&0xFFF00000){
		name[length++]=convertToHex((offset>>20)&15);
	}
	if(offset&0xFFFF0000){
		name[length++]=convertToHex((offset>>16)&15);
	}
	if(offset&0xFFFFF000){
		name[length++]=convertToHex((offset>>12)&15);
	}
	if(offset&0xFFFFFF00){
		name[length++]=convertToHex((offset>>8)&15);
	}
	if(offset&0xFFFFFFF0){
		name[length++]=convertToHex((offset>>4)&15);
	}
	name[length++]=convertToHex(offset&15);
	name[length]=0;
	return length;
}

char convertToHex(int i){
	if(i<0){
		return '0';
	}
	if(i<10){
		return (char)'0'+i;
	}
	if(i<16){
		return (char)'A'+i-10;
	}
	return '0';
}

char* getName(int sectionNumber,int offset){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	if(curS==0){
		return &emptyString;
	}
	curObj = getObject(curS,offset);
	if(curObj==0){
		return &emptyString;
	}
	return curObj->name;
}

struct DataRecord* lookupSectionDataRecord(int sectionNumber, FourCharCode key){
	struct Section* curS = getSection(sectionNumber);
	struct DataRecord* curRec;
	if(curS==0){
		return 0;
	}
	curRec = curS->dataList;
	if(curRec == 0){
		return 0;
	}
	while(curRec!=0&&curRec->key!=key){
		curRec = curRec->next;
	}
	return curRec;
}

struct DataRecord* lookupObjectDataRecord(int sectionNumber, int offset, FourCharCode key){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct DataRecord* curRec;
	if(curS==0){
		return 0;
	}
	curObj = getObject(curS, offset);
	if(curObj==0){
		return 0;
	}
	curRec = curObj->dataList;
	if(curRec == 0){
		return 0;
	}
	while(curRec!=0&&curRec->key!=key){
		curRec = curRec->next;
	}
	return curRec;
}

void* lookupSectionDRVal(int sectionNumber, FourCharCode key){
	struct DataRecord* dr = lookupSectionDataRecord(sectionNumber, key);
	if(dr==0){
		return 0;
	}
	return dr->value;
}

void* lookupObjectDRVal(int sectionNumber, int offset, FourCharCode key){
	struct DataRecord* dr = lookupObjectDataRecord(sectionNumber, offset, key);
	if(dr==0){
		return 0;
	}
	return dr->value;
}

OSStatus createSectionDataRecord(int sectionNumber, FourCharCode key, void* value, int valueSize){
	struct Section* curS = getSection(sectionNumber);
	struct DataRecord* curRec;
	void* copiedValue;
	if(curS==0){
		return -1;
	}
	curRec = (struct DataRecord*) malloc(sizeof(struct DataRecord));
	if(curRec==0){
		return -1;
	}
	copiedValue = (void*) malloc(valueSize);
	if(copiedValue==0){
		free((char*)curRec);
		return -1;
	}
	BlockMoveData(value, copiedValue, (Size)valueSize);
	curRec->key = key;
	curRec->value = copiedValue;
	curRec->valueSize = valueSize;
	curRec->next = curS->dataList;
	curS->dataList = curRec;
	return 0;
}

OSStatus createObjectDataRecord(int sectionNumber, int offset, FourCharCode key, void* value, int valueSize){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct DataRecord* curRec;
	void* copiedValue;
	if(curS==0){
		return -1;
	}
	curObj = getObject(curS, offset);
	if(curObj==0){
		noteOffset(sectionNumber, offset, 0);
		curObj = getObject(curS, offset);
		if(curObj==0){
			return -1;
		}
	}
	curRec = (struct DataRecord*) malloc(sizeof(struct DataRecord));
	if(curRec==0){
		return -1;
	}
	copiedValue = (void*) malloc(valueSize);
	if(copiedValue==0){
		return -1;
	}
	BlockMoveData(value, copiedValue, (Size)valueSize);
	curRec->key = key;
	curRec->value = copiedValue;
	curRec->valueSize = valueSize;
	curRec->next = curObj->dataList;
	curObj->dataList = curRec;
	return 0;
}

OSStatus addSectionInfo(int sectionNumber, FourCharCode key, void* value, int valueSize){
	struct DataRecord* oldDR = lookupSectionDataRecord(sectionNumber, key);
	struct DisasmModule* merger = firstModule;
	OSStatus result = -1;
	if(oldDR == 0){
		result = createSectionDataRecord(sectionNumber, key, value, valueSize);
	}else{
		while(merger!=0){
			result = merger->mergeSectionInfo(key, oldDR, value, valueSize);
			if(result==0){
				break;
			}
			merger = merger->next;
		}
	}
	if(result == 0){
		updateSection(sectionNumber);
	}
	return result;
}

OSStatus addObjectInfo(int sectionNumber, int offset, FourCharCode key, void* value, int valueSize){
	struct DataRecord* oldDR = lookupObjectDataRecord(sectionNumber, offset, key);
	struct DisasmModule* merger = firstModule;
	OSStatus result = -1;
	if(oldDR == 0){
		result = createObjectDataRecord(sectionNumber, offset, key, value, valueSize);
	}else{
		//fprintf(stderr, "addObjectInfo merge [ %d %d '%c%c%c%c' ]\n", sectionNumber, offset, (key>>24)&0xFF, (key>>16)&0xFF, (key>>8)&0xFF, key&0xFF);
		while(merger!=0){
			result = merger->mergeObjectInfo(key, oldDR, value, valueSize);
			if(result==0){
				break;
			}
			merger = merger->next;
		}
	}
	if(result == 0){
		updateObject(sectionNumber, offset);
	}
	return result;
}

void updateSection(int sectionNumber){
	struct Section* curS = getSection(sectionNumber);
	if(curS==0){
		return;
	}
	curS->numUpdates++;
}
void updateObject(int sectionNumber, int offset){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	if(curS==0){
		return;
	}
	curObj = getObject(curS, offset);
	if(curObj==0){
		return;
	}
	curS->numUpdates++;
	curObj->numUpdates++;
}

void markSectionAsProcessed(int sectionNumber, FourCharCode module){
	struct Section* curS = getSection(sectionNumber);
	struct DataRecord* oldDR = lookupSectionDataRecord(sectionNumber, module);// use the module's name as the key
	if(curS==0){
		return;
	}
	if(oldDR == 0){
		createSectionDataRecord(sectionNumber, module, &(curS->numUpdates), 4);
	}else{
		((int*)oldDR->value)[0] = curS->numUpdates;
	}
}

void markObjectAsProcessed(int sectionNumber, int offset, FourCharCode module){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct DataRecord* oldDR = lookupObjectDataRecord(sectionNumber, offset, module);
	if(curS==0){
		return;
	}
	curObj = getObject(curS, offset);
	if(curObj==0){
		return;
	}
	if(oldDR==0){
		createObjectDataRecord(sectionNumber, offset, module, &(curObj->numUpdates), 4);
	}else{
		((int*)oldDR->value)[0] = curObj->numUpdates;
	}
}

int isModuleDoneWithSection(struct DisasmModule* curM, struct Section* curS){
	FourCharCode modName = curM->name;
	struct DataRecord* modStamp = lookupSectionDataRecord(curS->number, modName);
	int* modStampValue;
	if(modStamp == 0){
		return 0;//if the module has never attempted to process the section, it is not done with it
	}
	modStampValue = (int*)modStamp->value;
	if(modStampValue[0]==curS->numUpdates){
		return 1;
	}
	return 0;
}

int getObjectEnd(struct Object* curObj){
	struct Section* curS = curObj->parent;
	struct Object* nextObj = curObj->next;
	if(nextObj != 0){
		return nextObj->offset-1;
	}
	return curS->size-1;
}
OSStatus printSection(FILE* printLoc, int sectionNumber){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct DataRecord* curDR;
	if(curS==0){
		fprintf(stderr,"invalid section number\n");
		return 1;
	}
	curDR = curS->dataList;
	while(curDR!=0){
		printSectionDR(printLoc, curDR);
		curDR = curDR->next;
	}
	curObj = curS->objectLL;
	if(curObj==0){
		printRaw(printLoc, curS->content, 0, curS->size);
		return 0;
	}
	if(curObj->offset!=0){
		printRaw(printLoc, curS->content, 0, curObj->offset-1);
	}
	while(curObj!=0){
		printObjectData(printLoc, sectionNumber, curObj->offset);
		curObj = curObj->next;
	}
	return 0;
}

OSStatus printObjectData(FILE* printLoc, int sectionNumber, int offset){
	struct Section* curS = getSection(sectionNumber);
	struct Object* curObj;
	struct DataRecord* curDR;
	struct DisasmModule* curM = firstModule;
	OSStatus result;
	if(curS==0){
		fprintf(stderr,"invalid section number\n");
		return -1;
	}
	curObj = getObject(curS, offset);
	if(curObj==0){
		fprintf(stderr,"invalid offset\n");
		return -2;
	}
	// TODO: actually print contents
	while(curM!=0){
		result = curM->printObjectData(printLoc, sectionNumber, offset, getObjectEnd(curObj));
		if(result == 0){
			return 0;
		}
		curM = curM->next;
	}
	return -3;
	/*fprintf(printLoc, "%s: ;(0x%08x, 0x%08x)\n", curObj->name, curS->number, curObj->offset);
	curDR = curObj->dataList;
	while(curDR!=0){
		printObjectDR(printLoc, curDR);
		curDR = curDR->next;
	}*/
	return 0;
}

void printAllSections(FILE* printLoc){
	struct Section* curS = firstSection;
	while(curS!=0){
		fprintf(printLoc,";Section %d:\n",curS->number);
		printSection(printLoc, curS->number);
		curS=curS->next;
	}
}

void printSectionDR(FILE* printLoc, struct DataRecord* dr){
	struct DisasmModule* curMod = firstModule;
	OSStatus result;
	while(curMod!=0){
		result = curMod->printSectionDR(printLoc, dr);
		if(result == 0){
			return;
		}
		curMod = curMod->next;
	}
	//if nothing knows about it, just give up and print the name
	fprintf(printLoc, ";DataRecord '%c%c%c%c': (0x%08x 0x0%08x)\n",(dr->key>>24)&255,(dr->key>>16)&255,(dr->key>>8)&255,dr->key&255, dr->value, dr->valueSize);
	/*if(0xDEAD1234 | ((int*)kBlessedBusErrorBait)[0]){
	
	}*/
}

void printObjectDR(FILE* printLoc, struct DataRecord* dr){
	struct DisasmModule* curMod = firstModule;
	OSStatus result;
	while(curMod!=0){
		result = curMod->printObjectDR(printLoc, dr);
		if(result == 0){
			return;
		}
		curMod = curMod->next;
	}
	//if nothing knows about it, just give up and print the name
	fprintf(printLoc, ";DataRecord '%c%c%c%c': (0x%08x 0x0%08x)\n",(dr->key>>24)&255,(dr->key>>16)&255,(dr->key>>8)&255,dr->key&255, dr->value, dr->valueSize);
	/*if(0x1234DEAD | ((int*)kBlessedBusErrorBait)[0]){
	
	}*/
}

#define safenChar(c) (c<32||c>126)?' ':c
void printRaw(FILE* printLoc, char* content, int startOffset, int endOffset){
	int i = startOffset;
	while(i<=endOffset){//original version
		if(i+3<=endOffset){
			fprintf(printLoc,"    DC.L 0x");
			print2HexDigits(printLoc,content[i]);
			print2HexDigits(printLoc,content[i+1]);
			print2HexDigits(printLoc,content[i+2]);
			print2HexDigits(printLoc,content[i+3]);
			fprintf(printLoc,"; '%c%c%c%c'\n", safenChar(content[i]), safenChar(content[i+1]), safenChar(content[i+2]), safenChar(content[i+3]));
			i+=4;
		}else{
			fprintf(printLoc,"    DC.B 0x");
			print2HexDigits(printLoc,content[i]);
			fprintf(printLoc,"; '%c'\n", safenChar(content[i]));
			i++;
		}
	}
}

void print2HexDigits(FILE* printLoc, char input){
	fputc(convertToHex((input>>4)&15), printLoc);
	fputc(convertToHex(input & 15), printLoc);
}

/*
while(i<=endOffset){
		if(i+3<=endOffset){
			fprintf(printLoc,"[0x%08x]: 0x", i);
			print2HexDigits(printLoc,content[i]);
			print2HexDigits(printLoc,content[i+1]);
			print2HexDigits(printLoc,content[i+2]);
			print2HexDigits(printLoc,content[i+3]);
			fprintf(printLoc,"\n");
			i+=4;
		}else{
			fprintf(printLoc,"[0x%08x]: 0x", i);
			print2HexDigits(printLoc,content[i]);
			fprintf(printLoc,"\n");
			i++;
		}
	}
*/