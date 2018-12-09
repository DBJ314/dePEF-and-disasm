#   File:       RTOCDump.make
#   Target:     RTOCDump


"{RTOCDumpDir}RTOCDump.c.x"  ƒ  "{RTOCDumpDir}RTOCDump.c" "{EngineDir}Disasm.h"
	{PPCC} "{RTOCDumpDir}RTOCDump.c" -o "{RTOCDumpDir}RTOCDump.c.x" -w off -i "{EngineDir}" {PPCCOptions}


"{RTOCDumpDir}RTOCDump"  ƒƒ  "{RTOCDumpDir}RTOCDump.c.x" {LibFiles-PPC} "{RTOCDumpDir}RTOCDump.make"
	PPCLink ∂
		-o "{RTOCDumpDir}RTOCDump" ∂
		"{RTOCDumpDir}RTOCDump.c.x" ∂
		"{EngineDir}Engine" ∂
		{LibFiles-PPC} ∂
		{Sym-PPC} ∂
		-mf -d ∂
		-export useRTOCDump ∂
		-t 'shlb' ∂
		-c '????' ∂
		-w ∂
		-xm s



### Required Dependencies ###

"{RTOCDumpDir}RTOCDump.c.x"  ƒ  "{RTOCDumpDir}RTOCDump.c"
