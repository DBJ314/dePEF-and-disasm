#   File:       RawDump.make
#   Target:     RawDump


"{RawDumpDir}RawDump.c.x"  ƒ  "{RawDumpDir}RawDump.c" "{EngineDir}Disasm.h"
	{PPCC} "{RawDumpDir}RawDump.c" -o "{RawDumpDir}RawDump.c.x" -w off -i "{EngineDir}" {PPCCOptions}


"{RawDumpDir}RawDump"  ƒƒ  "{RawDumpDir}RawDump.c.x" {LibFiles-PPC} "{RawDumpDir}RawDump.make"
	PPCLink ∂
		-o "{RawDumpDir}RawDump" ∂
		"{RawDumpDir}RawDump.c.x" ∂
		"{EngineDir}Engine" ∂
		{LibFiles-PPC} ∂
		{Sym-PPC} ∂
		-mf -d ∂
		-export useRawDump ∂
		-t 'shlb' ∂
		-c '????' ∂
		-w ∂
		-xm s



### Required Dependencies ###

"{RawDumpDir}RawDump.c.x"  ƒ  "{RawDumpDir}RawDump.c"
