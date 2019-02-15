#include "rawdisasm.h"

int main(int argc, char *argv[])
{
	FILE* input;
	
	int argPos;
	int inFound = 0;
	int inArrayLoc;
	int sscanfOut;
	int refSectNum;
	int refOffset;
	if(argc<2){
		fprintf(stderr, usageString, argv[0], argv[0]);
		return 1;
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
	size = ftell(input);
	rewind(input);
	fprintf(stdout,";input file size is %d bytes\n",size);
	buf = (char *)malloc(size+1);
	if(!buf) {
		fprintf(stderr, "Could not open allocate\n");
		return -2;
	}
	fread(buf, 1, size, input);
	fclose(input);
	
	useRawDump();
	usePPCDump();
	
	registerSection(0, buf, size, 0);
	
	processUserRefs();
	
	runDisassembly();
	printAllSections(stdout);
	return 0;
}

void noteUserRef(int sectionNumber, int offset, int isCode){
	struct UserReference* ur = (struct UserReference*)malloc(sizeof(struct UserReference));
	if(!ur){
		fprintf(stderr, "unable to allocate user ref structure. Disassembly might be incorrect\n");
		return;
	}
	fprintf(stderr, "User Reference: %d, 0x%08x, %d\n", sectionNumber, offset, isCode);
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
		/*if(ur->isCode){
			curRWX.called = 1;
			curRWX.read = 0;
		}else{
			curRWX.called = 0;
			curRWX.read = 1;
		}
		noteOffset(ur->sectionNumber, ur->offset, 0);
		addObjectInfo(ur->sectionNumber, ur->offset, kRWX, &curRWX, sizeof(struct RWX_Record));*/
		if(ur->isCode){
			noteESym(ur->sectionNumber, ur->offset, kCode, 0);
		}else{
			noteESym(ur->sectionNumber, ur->offset, kData, 0);
		}
		ur = ur->next;
	}
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