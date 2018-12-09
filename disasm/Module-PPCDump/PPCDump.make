#   File:       PPCDump.make
#   Target:     PPCDump


"{PPCDumpDir}PPCDump.c.x"  ƒ  "{PPCDumpDir}PPCDump.c" "{EngineDir}Disasm.h"
	{PPCC} "{PPCDumpDir}PPCDump.c" -o "{PPCDumpDir}PPCDump.c.x" -w off -i "{EngineDir}" {PPCCOptions}


"{PPCDumpDir}PPCDump"  ƒƒ  "{PPCDumpDir}PPCDump.c.x" {LibFiles-PPC} "{PPCDumpDir}PPCDump.make"
	PPCLink ∂
		-o "{PPCDumpDir}PPCDump" ∂
		"{PPCDumpDir}PPCDump.c.x" ∂
		"{EngineDir}Engine" ∂
		{LibFiles-PPC} ∂
		{Sym-PPC} ∂
		-mf -d ∂
		-export usePPCDump ∂
		-t 'shlb' ∂
		-c '????' ∂
		-w ∂
		-xm s



### Required Dependencies ###

"{PPCDumpDir}PPCDump.c.x"  ƒ  "{PPCDumpDir}PPCDump.c"
