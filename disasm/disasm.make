#build file for disassembler and all modules
				
MainDir		= :

Sym-PPC         = -sym on

PPCCOptions     = -align packed {Sym-PPC} 

LibFiles-PPC    =  ∂
				  "{SharedLibraries}InterfaceLib" ∂
				  "{SharedLibraries}StdCLib" ∂
				  "{SharedLibraries}MathLib" ∂
				  "{PPCLibraries}StdCRuntime.o" ∂
				  "{PPCLibraries}PPCCRuntime.o" ∂
				  "{PPCLibraries}PPCToolLibs.o"

EngineDir 	= "{MainDir}Engine:"

RawDumpDir	= "{MainDir}Module-RawDump:"

PPCDumpDir	= "{MainDir}Module-PPCDump:"

RTOCDumpDir		= "{MainDir}Module-RTOCDump:"

Disasm  ƒƒ  "{EngineDir}Engine" "{RawDumpDir}RawDump" "{PPCDumpDir}PPCDump" "{RTOCDumpDir}RTOCDump" "{MainDir}disasm.make"
	Delete "{MainDir}Disasm" -i
	MergeFragment "{EngineDir}Engine" "{RawDumpDir}RawDump" "{PPCDumpDir}PPCDump" "{RTOCDumpDir}RTOCDump" "{MainDir}Disasm" -d -x

#include "{EngineDir}Engine.make"
#include "{RawDumpDir}RawDump.make"
#include "{PPCDumpDir}PPCDump.make"
#include "{RTOCDumpDir}RTOCDump.make"