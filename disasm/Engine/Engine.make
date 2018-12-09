#   File:       Engine.make
#   Target:     Engine
#   Created:    Sunday, January 28, 2018 10:22:57 PM


MAKEFILE        = disasm-engine.make
•MondoBuild•    = {MAKEFILE}  # Make blank to avoid rebuilds when makefile is modified

ObjDir          = :
Includes        = 


"{EngineDir}Engine.c.x" ƒ "{EngineDir}Engine.c" "{EngineDir}Disasm.h" "{EngineDir}Engine.make"
	{PPCC} "{EngineDir}Engine.c" -o "{EngineDir}Engine.c.x" {PPCCOptions}



"{EngineDir}Engine"  ƒƒ "{EngineDir}Engine.c.x" {LibFiles-PPC} "{EngineDir}Engine.make" "{EngineDir}Exports"
	PPCLink ∂
		-o {Targ} ∂
		"{EngineDir}Engine.c.x" ∂
		{LibFiles-PPC} ∂
		{Sym-PPC} ∂
		-@export "{EngineDir}Exports" ∂
		-fragname Disasm ∂
		-mf -d ∂
		-t 'shlb' ∂
		-c '????' ∂
		-xm s
 