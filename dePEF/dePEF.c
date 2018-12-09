#include "dePEF.h"

struct Frag target;

int main(int argc, char *argv[])
{
	FILE* input;
	int error;
	
	int argPos;
	int inFound = 0;
	int inArrayLoc;
	int sscanfOut;
	int refSectNum;
	int refOffset;
	if(argc<2){
		fprintf(stderr, usageString, argv[0], argv[0]);
		return 0;
	}
	for(argPos = 1; argPos<argc; argPos++){
		if(argv[argPos][0]=='-'){
			switch(argv[argPos][1]){
				case 'c':
				case 'C':
					if(argc-argPos-1<2){
						fprintf(stderr, "Error: -c (argv[%d]) requires 2 arguments after it\n", argPos);
						fprintf(stderr, usageString, argv[0], argv[0]);
						return 0;
					}
					sscanfOut = sscanf(argv[argPos+1], "%x", &refSectNum);
					if(sscanfOut!=1){
						fprintf(stderr, "error reading 1st arg of '-c' at (argv[%d]). Maybe it isn't hexadecimal\n", argPos);
						fprintf(stderr, usageString, argv[0], argv[0]);
						return 0;
					}
					sscanfOut = sscanf(argv[argPos+2], "%x", &refOffset);
					if(sscanfOut!=1){
						fprintf(stderr, "error reading 2nd arg of '-c' at (argv[%d]). Maybe it isn't hexadecimal\n", argPos);
						fprintf(stderr, usageString, argv[0], argv[0]);
						return 0;
					}
					argPos+=2;
					noteUserRef(refSectNum, refOffset, 1);
					break;
				case 'd':
				case 'D':
					if(argc-argPos-1<2){
						fprintf(stderr, "Error: -d (argv[%d]) requires 2 arguments after it\n", argPos);
						fprintf(stderr, usageString, argv[0], argv[0]);
						return 0;
					}
					sscanfOut = sscanf(argv[argPos+1], "%x", &refSectNum);
					if(sscanfOut!=1){
						fprintf(stderr, "error reading 1st arg of '-d' at (argv[%d]). Maybe it isn't hexadecimal\n", argPos);
						fprintf(stderr, usageString, argv[0], argv[0]);
						return 0;
					}
					sscanfOut = sscanf(argv[argPos+2], "%x", &refOffset);
					if(sscanfOut!=1){
						fprintf(stderr, "error reading 2nd arg of '-d' at (argv[%d]). Maybe it isn't hexadecimal\n", argPos);
						fprintf(stderr, usageString, argv[0], argv[0]);
						return 0;
					}
					argPos+=2;
					noteUserRef(refSectNum, refOffset, 0);
					break;
				default:
				case 'h':
				case 'H':
					fprintf(stderr, usageString, argv[0], argv[0]);
					return 0;
			}
		}else{
			if(inFound){
				fprintf(stderr, "only  one input file allowed\n");
				fprintf(stderr, usageString, argv[0], argv[0]);
				return 0;
			}
			inFound = 1;
			inArrayLoc = argPos;
		}
	}
	if(!inFound){
		fprintf(stderr, "you must specify an input file\n");
		fprintf(stderr, usageString, argv[0], argv[0]);
		return 0;
	}
	input = fopen(argv[inArrayLoc],"r");
	if(input==0){
		fprintf(stderr,"Error: \'%s\' could not be opened\n",argv[inArrayLoc]);
		return 1;
	}
	fseek(input, 0L, SEEK_END);
	target.maxLength = ftell(input);
	rewind(input);
	fprintf(stdout,";input file size is %d bytes\n",target.maxLength);
	target.buf = (char *)malloc(target.maxLength+1);
	if(!target.buf) {
		fprintf(stderr, "Could not open allocate\n");
		return -2;
	}
	fread(target.buf, 1, target.maxLength, input);
	fclose(input);
	
	useRawDump();
	usePPCDump();
	useRTOCDump();
	error = decodeFragHdr();
	if(error){
		goto cleanup;
	}
	error = processSectionHdrs();
	if(error){
		goto cleanup;
	}
	processUserRefs();
	runDisassembly();
	printAllSections(stdout);
	cleanup:
	return 0;
}

void noteUserRef(int sectionNumber, int offset, int isCode){
	struct UserReference* ur = (struct UserReference*)malloc(sizeof(struct UserReference));
	if(!ur){
		fprintf(stderr, "unable to allocate user ref structure. Disassembly might be incorrect\n");
		return;
	}
	ur->next = firstUR;
	ur->sectionNumber = sectionNumber;
	ur->offset = offset;
	ur->isCode = isCode;
	firstUR = ur;
}

void processUserRefs(){
	struct UserReference* ur = firstUR;
	struct RWX_Record curRWX = {0,0,0,0};
	while(ur){
		if(ur->isCode){
			curRWX.called = 1;
			curRWX.read = 0;
		}else{
			curRWX.called = 0;
			curRWX.read = 1;
		}
		noteOffset(ur->sectionNumber, ur->offset, 0);
		addObjectInfo(ur->sectionNumber, ur->offset, kRWX, &curRWX, sizeof(struct RWX_Record));
		ur = ur->next;
	}
}
int decodeFragHdr(){
	int error = 0;
	int var;
	var=getI(0);
	if(var!=0x4A6F7921){
		fprintf(stderr,"tag1 is %x instead of 0x4A6F7921",var);
		return 1;
	}
	var=getI(1);
	if(var!=0x70656666){
		fprintf(stderr,"tag2 is %x instead of 0x70656666",var);
		return 1;
	}
	var=getI(2);
	if(var!=0x70777063){
		fprintf(stderr,"this only handles ppc pefs",var);
		return 1;
	}
	if(getI(3)!=1){
		fprintf(stderr,"this only handles the pef v1 format");
		return 1;
	}
	fprintf(stdout,";dateTimeStamp %x\n;oldDefVers: %x\n;oldImpVers: %x\n;curVers: %x\n",getI(4),getI(5),getI(6),getI(7));
	target.numSections=getS(16);
	target.instSections=getS(17);
	fprintf(stdout,";total sections: %d\n;instantiated sections: %d\n",target.numSections,target.instSections);
	return error;
}

int processSectionHdrs(){
	int error = 0;
	struct PEFSectionHeader* currentPEFHdr;
	int numSections = target.numSections;
	int sectionNumber = 0;
	while((numSections --> 0)&&(error==0)){
		currentPEFHdr = (struct PEFSectionHeader*)((char*)target.buf+40+(sectionNumber*sizeof(struct PEFSectionHeader)));
		error = decodePEFSectionHdr(currentPEFHdr, sectionNumber);
		sectionNumber++;
	}

	return error;
}

int decodePEFSectionHdr(struct PEFSectionHeader* PEFHdr,int sectionNumber){
	int error = 0;
	fprintf(stdout,";Section %d, Type: %d (",sectionNumber,PEFHdr->sectionKind);
	if(PEFHdr->defaultAddress!=0){
		fprintf(stderr,"Error: nonzero default addresses not implemented\n");
		return -1;
	}
	switch(PEFHdr->sectionKind){
		case 0://if code section
			fprintf(stdout,"Code)\n");
			registerSection(sectionNumber, (char*)((target.buf)+(PEFHdr->containerOffset)), PEFHdr->totalSize, 0);
			break;
		case 1://if raw data
			fprintf(stdout,"Raw Data)\n");
			registerSection(sectionNumber, (char*)((target.buf)+(PEFHdr->containerOffset)), PEFHdr->totalSize, 0);
			break;
		case 2:
			fprintf(stdout,"Compressed Data)\n");
			decodePIData(PEFHdr, sectionNumber);
			break;
		case 3://if constant
			fprintf(stdout,"Constant Data)\n");
			registerSection(sectionNumber, (char*)((target.buf)+(PEFHdr->containerOffset)), PEFHdr->totalSize, 0);
			break;
		case 4://if loader
			fprintf(stdout,"Loader)\n");
			decodeLoader(PEFHdr, sectionNumber);
			break;
		default:
			fprintf(stdout,"Unknown)\n");
			break;
	
	}
	return error;
}

void decodePIData(struct PEFSectionHeader* PEFHdr, int sectionNumber){
	char* data = (char*)calloc(PEFHdr->totalSize,1);
	char* pattern = (char*)((target.buf)+(PEFHdr->containerOffset));
	int readPoint = 0;
	int writePoint = 0;
	int opcode;
	int firstArg;
	int secondArg;
	int thirdArg;
	int commonPoint;
	int i;
	if(data==0){
		fprintf(stderr,"out of memory\n");
		return;
	}
	while(readPoint<PEFHdr->packedSize){
		opcode = (pattern[readPoint]&0xE0)>>5;
		firstArg=pattern[readPoint++]&31;
		if(firstArg==0){
			firstArg=decodePIArg(pattern,&readPoint,0);
		}
		switch(opcode){
			case 0:
				writePoint+=firstArg;
				break;
			case 1:
				memcpy((void*)(data+writePoint), (void*)(pattern+readPoint), firstArg);
				readPoint+=firstArg;
				writePoint+=firstArg;
				break;
			case 2:
				secondArg=decodePIArg(pattern,&readPoint,0)+1;
				for(i=0;i<secondArg;i++){
					memcpy((void*)(data+writePoint), (void*)(pattern+readPoint), firstArg);
					writePoint+=firstArg;
				}
				readPoint+=firstArg;
				break;
			case 3:
				secondArg=decodePIArg(pattern,&readPoint,0);
				thirdArg=decodePIArg(pattern,&readPoint,0);
				commonPoint = readPoint;
				readPoint+=firstArg;
				memcpy((void*)(data+writePoint),(void*)(pattern+commonPoint),firstArg);
				writePoint+=firstArg;
				for(i=0;i<thirdArg;i++){
					memcpy((void*)(data+writePoint),(void*)(pattern+readPoint),secondArg);
					writePoint+=secondArg;
					readPoint+=secondArg;
					memcpy((void*)(data+writePoint),(void*)(pattern+commonPoint),firstArg);
					writePoint+=firstArg;
				}
				break;
			case 4:
				secondArg=decodePIArg(pattern,&readPoint,0);
				thirdArg=decodePIArg(pattern,&readPoint,0);
				writePoint+=firstArg;
				for(i=0;i<thirdArg;i++){
					memcpy((void*)(data+writePoint),(void*)(pattern+readPoint),secondArg);
					writePoint+=secondArg+firstArg;
					readPoint+=secondArg;
				}
				break;
		}
	}
	registerSection(sectionNumber,data,PEFHdr->totalSize, 0);
}

int decodePIArg(char* pattern, int* readPoint, int prevData){
	int temp = pattern[(*readPoint)++];
	if((temp&0x80)==0){
		return temp+prevData;
	}
	return decodePIArg(pattern, readPoint, (((temp&127)+prevData)<<7));
}

void decodeLoader(struct PEFSectionHeader* PEFHdr, int sectionNumber){
	struct PEFLoaderInfoHeader* PEFLodr = (struct PEFLoaderInfoHeader*)((char*)target.buf+PEFHdr->containerOffset);
	struct PEFImportedLibrary* PEFLibList = (struct PEFImportedLibrary*)((struct PEFLoaderInfoHeader*)PEFLodr + 1);
	struct PEFLoaderRelocationHeader* PEFRelHdr;// = (struct PEFLoaderRelocationHeader*)(((char*)PEFLodr) + (PEFLodr->relocInstrOffset));

	struct PEFLoaderRelocationHeader* curRelHdr;
	
	char* stringList = (char*)PEFLodr+PEFLodr->loaderStringsOffset;
	int numImports = PEFLodr->totalImportedSymbolCount;
	int numImportLibs = PEFLodr->importedLibraryCount;
	int numRelSects = PEFLodr->relocSectionCount;
	
	int* importSymTbl = (int*)((struct PEFImportedLibrary*)PEFLibList + (numImportLibs));
	UInt16* relOpBase = (UInt16*)((char*)PEFLodr + (PEFLodr->relocInstrOffset));
	int hashTablePower = PEFLodr->exportHashTablePower;
	int hashTableSize = 1;
	int* exportKeyTable;
	struct PEFExportedSymbol* exportSymTable;
	int exportIndex = 0;
	int thisExportKey;
	struct PEFExportedSymbol* thisExportSym;
	int exportNameIndex;
	int exportNameLen;
	char savedNameChar;
	/* variables used to decipher relocations */
	int rtocSec = -1;
	int rtocOffset = -1;
	struct TVec_Record tvec;
	struct RWX_Record codeRWX = {0,0,0,0};
	/* state variables for the relocation decoder */
	int relHdrIndex;
	UInt16* relOps;
	int relocIndex;
	int relocLen;
	short opcode;
	int relSectNum = 0;
	int relSectIndex = 0;
	int importIndex = 0;
	int sectC = 0;//number of section sectionC var would point to, not actual address
	int sectD = 1;
	int i;
	int inLoop;
	int loopInstrIndex;//value of relocIndex when instr is encountered
	int numLoops;
	codeRWX.called = 1;
	PEFRelHdr = (struct PEFLoaderRelocationHeader*)((int*)importSymTbl+numImports);
	while(hashTablePower --> 0){
		hashTableSize <<= 1;
	}
	exportKeyTable = (int*)((char*)PEFLodr+PEFLodr->exportHashOffset+(hashTableSize*4));
	exportSymTable = (struct PEFExportedSymbol*)((char*)exportKeyTable + (PEFLodr->exportedSymbolCount*4));
	
	for(relHdrIndex = 0; relHdrIndex < numRelSects; relHdrIndex++){
		curRelHdr = PEFRelHdr + (relHdrIndex);
		relSectNum = curRelHdr->sectionIndex;
		relSectIndex = 0;
		relOps = (UInt16*)((char*)relOpBase + curRelHdr->firstRelocOffset);
		relocIndex = 0;
		relocLen = curRelHdr->relocCount;
		importIndex = 0;
		sectC = 0;
		sectD = 1;
		inLoop = 0;
		loopInstrIndex = 0;
		numLoops = 0;
		while(relocIndex<relocLen){
			opcode = relOps[relocIndex++];
			if((opcode & 0xC000)==0){
				//RelocBySectDWithSkip
				relSectIndex += ((opcode & 0x3FC0)>>6) * 4;
				for(i = 0; i < (opcode & 0x3F); i++){
					crossReference(sectD, getSectVal(relSectNum, relSectIndex), relSectNum, relSectIndex, kLinkUnknown, 0);
					relSectIndex+=4;
				}
			}else if((opcode & 0xFF00)==0x4000){
				//RelocBySectC
				for(i = 0; i < (opcode & 0xFF) + 1; i++){
					crossReference(sectC, getSectVal(relSectNum, relSectIndex), relSectNum, relSectIndex, kLinkUnknown, 0);
					relSectIndex+=4;
				}
			}else if((opcode & 0xFE00)==0x4200){
				//RelocBySectD
				for(i = 0; i < (opcode & 0xFF) + 1; i++){
					crossReference(sectD, getSectVal(relSectNum, relSectIndex), relSectNum, relSectIndex, kLinkUnknown, 0);
					relSectIndex+=4;
				}
			}else if((opcode & 0xFE00)==0x4400){
				//RelocTVector12
				for(i = 0; i < (opcode & 0xFF) + 1; i++){
					tvec.sectionNumber = sectC;
					tvec.offset = getSectVal(relSectNum, relSectIndex);
					crossReference(sectC, tvec.offset, relSectNum, relSectIndex, kLinkPtr, 0);
					addObjectInfo(relSectNum, relSectIndex, kTVec, &tvec, sizeof(struct TVec_Record));
					addObjectInfo(sectC, tvec.offset, kRWX, &codeRWX, sizeof(struct RWX_Record));
					relSectIndex+=4;
					crossReference(sectD, getSectVal(relSectNum, relSectIndex), relSectNum, relSectIndex, kLinkPtr, 0);
					noteRTOC(&rtocSec, &rtocOffset, sectD, getSectVal(relSectNum, relSectIndex));
					relSectIndex+=8;
				}
			}else if((opcode & 0xFE00)==0x4600){
				//RelocTVector8
				for(i = 0; i < (opcode & 0xFF) + 1; i++){
					tvec.sectionNumber = sectC;
					tvec.offset = getSectVal(relSectNum, relSectIndex);
					crossReference(sectC, tvec.offset, relSectNum, relSectIndex, kLinkPtr, 0);
					addObjectInfo(relSectNum, relSectIndex, kTVec, &tvec, sizeof(struct TVec_Record));
					addObjectInfo(sectC, tvec.offset, kRWX, &codeRWX, sizeof(struct RWX_Record));
					relSectIndex+=4;
					crossReference(sectD, getSectVal(relSectNum, relSectIndex), relSectNum, relSectIndex, kLinkPtr, 0);
					noteRTOC(&rtocSec, &rtocOffset, sectD, getSectVal(relSectNum, relSectIndex));
					relSectIndex+=4;
				}
			}else if((opcode & 0xFE00)==0x4800){
				//RelocVTable8
				for(i = 0; i < (opcode & 0xFF) + 1; i++){
					crossReference(sectD, getSectVal(relSectNum, relSectIndex), relSectNum, relSectIndex, kLinkUnknown, 0);
					relSectIndex+=8;
				}
			}else if((opcode & 0xFE00)==0x4A00){
				//RelocImportRun
				for(i = 0; i < (opcode & 0xFF) + 1; i++){
					noteISym(relSectNum, relSectIndex, stringList, importSymTbl, PEFLibList, numImportLibs, importIndex);
					relSectIndex +=4;
					importIndex +=1;
				}
			}else if((opcode & 0xFE00)==0x6000){
				//RelocSmByImport
				importIndex = opcode & 0x01FF;
				noteISym(relSectNum, relSectIndex, stringList, importSymTbl, PEFLibList, numImportLibs, importIndex);
				relSectIndex +=4;
				importIndex +=1;
			}else if((opcode & 0xFE00)==0x6200){
				//RelocSmSetSectC
				sectC = opcode & 0x01FF;
				if(getSection(sectC)==0){
					fprintf(stderr, "error: sectC set to invalid section number\n");
				}
			}else if((opcode & 0xFE00)==0x6400){
				//RelocSmSetSectD
				sectD = opcode & 0x01FF;
				if(getSection(sectD)==0){
					fprintf(stderr, "error: sectD set to invalid section number\n");
				}
			}else if((opcode & 0xFE00)==0x6600){
				//RelocSmBySection
				crossReference(opcode&0x01FF, getSectVal(relSectNum, relSectIndex), relSectNum, relSectIndex, kLinkUnknown, 0);
				relSectIndex += 4;
			}else if((opcode & 0xF000)==0x8000){
				//RelocIncrPosition
				relSectIndex += (opcode & 0x0FFF)+1;
			}else if((opcode & 0xF000)==0x9000){
				//RelocSmRepeat
				if(inLoop){
					if(relocIndex != loopInstrIndex){
						fprintf(stderr, "error: nesting of RelocSmRepeat or RelocLgRepeat forbidden\n");
						return;
					}
					if(numLoops == 0){
						inLoop = 0;
					}else {
						numLoops--;
						relocIndex -= ((opcode&0x0F00)>>8)+2;//hopefully no off-by-one errors here
					}
				}else{
					inLoop = 1;
					loopInstrIndex = relocIndex;//keep track of where we are to prevent nesting issues
					numLoops = opcode & 0x00FF;
					relocIndex -= ((opcode&0x0F00)>>8)+2;//hopefully no off-by-one errors here
				}
			}else if((opcode&0xFC00)==0xA000){
				//RelocSetPosition
				relSectIndex = ((opcode&0x03FF)<<16)+relOps[relocIndex++];//a rare multi-word instruction
			}else if((opcode&0xFC00)==0xA400){
				//RelocLgByImport
				importIndex = ((opcode&0x03FF)<<16)+relOps[relocIndex++];//a rare multi-word instruction
			}else if((opcode&0xFC00)==0xB000){
				//RelocLgRepeat
				if(inLoop){
					if(relocIndex != loopInstrIndex){
						fprintf(stderr, "error: nesting of RelocSmRepeat or RelocLgRepeat forbidden\n");
						return;
					}
					if(numLoops == 0){
						inLoop = 0;
						relocIndex++;//a 2-word instruction
					}else {
						numLoops--;
						relocIndex -= ((opcode&0x0F00)>>8)+2;//hopefully no off-by-one errors here
					}
				}else{
					inLoop = 1;
					loopInstrIndex = relocIndex;//keep track of where we are to prevent nesting issues
					numLoops = ((opcode&0x003F)<<16)+relOps[relocIndex];
					relocIndex -= ((opcode&0x03C0)>>6)+2;//hopefully no off-by-one errors here
				}
			}else if((opcode&0xFFC0)==0xB400){
				//RelocLgSetOrBySection_0000
				crossReference(((opcode&0x3F)<<16)+relOps[relocIndex++], getSectVal(relSectNum, relSectIndex), relSectNum, relSectIndex, kLinkUnknown, 0);
				relSectIndex += 4;
			}else if((opcode&0xFFC0)==0xB440){
				//RelocLgSetOrBySection_0001
				sectC = ((opcode&0x3F)<<16)+relOps[relocIndex++];
				if(getSection(sectC)==0){
					fprintf(stderr, "error: sectC set to invalid section number\n");
				}
			}else if((opcode&0xFFC0)==0xB480){
				//RelocLgSetOrBySection_0010
				sectD = ((opcode&0x3F)<<16)+relOps[relocIndex++];
				if(getSection(sectD)==0){
					fprintf(stderr, "error: sectD set to invalid section number\n");
				}
			}else{
				fprintf(stderr, "error: unknown reloc opcode '%04x'\n", opcode);
			}
		}
	}
	if(PEFLodr->mainSection != -1){
		noteESym(PEFLodr->mainSection, PEFLodr->mainOffset, 0x4D61696E /* 'Main' */, "__start");
	}
	if(PEFLodr->initSection != -1){
		noteESym(PEFLodr->initSection, PEFLodr->initOffset, 0x496E6974 /* 'Init' */, "__init");
	}
	if(PEFLodr->termSection != -1){
		noteESym(PEFLodr->termSection, PEFLodr->termOffset, 0x5465726D /* 'Term' */, "__term");
	}
	for(exportIndex = 0; exportIndex < PEFLodr->exportedSymbolCount; exportIndex++){
		thisExportKey = exportKeyTable[exportIndex];
		thisExportSym = exportSymTable+exportIndex;
		exportNameIndex = (thisExportSym->classAndName)&0x00FFFFFF;
		exportNameLen = ((thisExportKey>>16)&0x0000FFFF);
		savedNameChar = stringList[exportNameIndex+exportNameLen];
		stringList[exportNameIndex+exportNameLen] = 0;//make string null-terminated momentarily
		switch((thisExportSym->classAndName>>24)&0x0F){
			case 0://kPEFCodeSymbol
				noteESym(thisExportSym->sectionIndex, thisExportSym->symbolValue, kCode, stringList + exportNameIndex);
				break;
			case 1://kPEFDataSymbol
				noteESym(thisExportSym->sectionIndex, thisExportSym->symbolValue, kData, stringList + exportNameIndex);
				break;
			case 2://kPEFTVectSymbol
				noteESym(thisExportSym->sectionIndex, thisExportSym->symbolValue, kTVec, stringList + exportNameIndex);
				break;
			case 3://kPEFTOCSymbol
				noteESym(thisExportSym->sectionIndex, thisExportSym->symbolValue, kTOC, stringList + exportNameIndex);
				break;
			case 4://kPEFGlueSymbol
				noteESym(thisExportSym->sectionIndex, thisExportSym->symbolValue, kGlue, stringList + exportNameIndex);
				break;
		}
		stringList[exportNameIndex+exportNameLen] = savedNameChar;
	}
}

void noteISym(int sectionNumber, int offset, char* stringList, int* importSymTbl, struct PEFImportedLibrary* PEFLibList, int numImportLibs, int importIndex){
	struct PEFImportedLibrary* curImpLib;
	struct ISym_Record isym;
	curImpLib = getSourceLib(PEFLibList, numImportLibs, importIndex);
	isym.libName = (char*)stringList + curImpLib->nameOffset;
	isym.name = (char*)(stringList + (importSymTbl[importIndex]&0x00FFFFFF));
	isym.weak = ((importSymTbl[importIndex]&0x80000000)!=0);
	switch((importSymTbl[importIndex]&0x0F000000)>>24){
		case 0://kPEFCodeSymbol
			isym.type = kCode;
			break;
		default://assume kData if type unknown
		case 1://kPEFDataSymbol
			isym.type = kData;
			break;
		case 2://kPEFTVectSymbol
			isym.type = kTVec;
			break;
		case 3://kPEFTOCSymbol
			isym.type = kTOC;
			break;
		case 4://kPEFGlueSymbol
			isym.type = kGlue;
			break;
	}
	noteOffset(sectionNumber, offset, isym.name);
	addObjectInfo(sectionNumber, offset, kISym, &isym, sizeof(struct ISym_Record));
}
void noteESym(int sectionNumber, int offset, FourCharCode type, char* suggestedName){
	struct ESym_Record er;
	struct RWX_Record RWr;
	struct RWX_Record pointedRWr;
	struct TVec_Record* TVr;
	struct Section* pointedS;
	struct Object* pointedObj;
	noteOffset(sectionNumber, offset, suggestedName);
	er.type = type;
	addObjectInfo(sectionNumber, offset, kESym, (void*)&er, sizeof(struct ESym_Record));
	RWr.read = 0; RWr.written = 0; RWr.called = 0; RWr.branched = 0;
	pointedRWr.read = 0; pointedRWr.written = 0; pointedRWr.called = 1; pointedRWr.branched = 0;
	switch(type){
		case kCode:
		case kGlue:
			RWr.called = 1;
			break;
		case kData:
			RWr.read = 1;
			break;
		case kTVec:
		case kInit:
		case kTerm:
		case kMain:
			RWr.read = 1;
			TVr = (struct TVec_Record*)lookupObjectDRVal(sectionNumber, offset, kTVec);
			if(TVr!=0){
				pointedS = getSection(TVr->sectionNumber);
				if(pointedS == 0){
					break;
				}
				pointedObj = getObject(pointedS, TVr->offset);
				if(pointedObj == 0){
					break;
				}
				if(suggestedName!=0){
					pointedObj->name[0]='.';
					BlockMoveData(suggestedName, &(pointedObj->name[1]), strlen(suggestedName)+1);
				}
				addObjectInfo(TVr->sectionNumber, TVr->offset, kRWX, &pointedRWr, sizeof(struct RWX_Record));
			}
			break;
		default:
			fprintf(stderr, "unknown ESym type 0x%08x\n", type);
			break;
	}
	addObjectInfo(sectionNumber, offset, kRWX, &RWr, sizeof(struct RWX_Record));
}

void noteRTOC(int* oldRSect, int* oldROffset, int newRSect, int newROffset){
	struct Section* curS = firstSection;
	struct RTOC_Record rr;
	if(*oldRSect != -1 || *oldROffset != -1){
		if(*oldRSect != newRSect || *oldROffset != newROffset){
			fprintf(stderr, "more than one rtoc? (%08x, %08x) and (%08x, %08x)\n", *oldRSect, *oldROffset, newRSect, newROffset);
		}
		return;
	}
	*oldRSect = newRSect;
	*oldROffset = newROffset;
	rr.sectionNumber = newRSect;
	rr.offset = newROffset;
	while(curS!=0){
		addSectionInfo(curS->number, kRTOC, &rr, sizeof(struct RTOC_Record));
		curS = curS->next;
	}
}
struct PEFImportedLibrary* getSourceLib(struct PEFImportedLibrary* PEFLibList, int libCount, int symbolIndex){
	int i;
	int libFirstSymbol;
	int libLastSymbol;
	while(i<libCount){
		libFirstSymbol = PEFLibList[i].firstImportedSymbol;
		libLastSymbol = libFirstSymbol + PEFLibList[i].importedSymbolCount - 1;
		if(symbolIndex>=libFirstSymbol && symbolIndex<= libLastSymbol){
			return PEFLibList + i;
		}
		i++;
	}
	return 0;
}

int getI(int i){
	int *ba = (int*)target.buf;
	if((i*4)>=target.maxLength){
		return 0;
	}
	return ba[i];
}
int* getO(int i){
	int* ba = (int*)target.buf+i;
	if(i>=target.maxLength){
		return 0;
	}
	return ba;
}
short getS(int i){
	short *ba = (short*)target.buf;
	if((i*2)>=target.maxLength){
		return 0;
	}
	return ba[i];
}

