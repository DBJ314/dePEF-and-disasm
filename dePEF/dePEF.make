#   File:       dePEF.make
#   Target:     dePEF
#   Created:    Monday, December 18, 2017 04:29:59 PM


MAKEFILE        = dePEF.make
•MondoBuild•    = {MAKEFILE}  # Make blank to avoid rebuilds when makefile is modified

ObjDir          = :
Includes        =  ∂
				  -i :

Sym-PPC         = -sym full

PPCCOptions     = {Includes} -align packed {Sym-PPC} 


### Source Files ###

SrcFiles        =  ∂
				  dePEF.c


### Object Files ###

ObjFiles-PPC    =  ∂
				  "{ObjDir}dePEF.c.x" ∂
				  "{ObjDir}Disasm"


### Libraries ###

LibFiles-PPC    =  ∂
				  "{SharedLibraries}InterfaceLib" ∂
				  "{SharedLibraries}StdCLib" ∂
				  "{SharedLibraries}MathLib" ∂
				  "{PPCLibraries}StdCRuntime.o" ∂
				  "{PPCLibraries}PPCCRuntime.o" ∂
				  "{PPCLibraries}PPCToolLibs.o"


### Default Rules ###

.c.x  ƒ  .c  {•MondoBuild•}
	{PPCC} {depDir}{default}.c -o {targDir}{default}.c.x {PPCCOptions}


### Build Rules ###

dePEF  ƒƒ  {ObjFiles-PPC} {LibFiles-PPC} {•MondoBuild•}
	PPCLink ∂
		-o {Targ} ∂
		{ObjFiles-PPC} ∂
		{LibFiles-PPC} ∂
		{Sym-PPC} ∂
		-mf -d ∂
		-t 'MPST' ∂
		-c 'MPS '



### Required Dependencies ###

"{ObjDir}dePEF.c.x"  ƒ  dePEF.c


### Optional Dependencies ###
### Build this target to generate "include file" dependencies. ###

Dependencies  ƒ  $OutOfDate
	MakeDepend ∂
		-append {MAKEFILE} ∂
		-ignore "{CIncludes}" ∂
		-objdir "{ObjDir}" ∂
		-objext .x ∂
		{Includes} ∂
		{SrcFiles}


#*** Dependencies: Cut here ***
# These dependencies were produced at 12:14:15 PM on Sun, Jan 28, 2018 by MakeDepend

:dePEF.c.x	ƒ  ∂
	:dePEF.c ∂
	:dePEF.h ∂
	:disasm.h

