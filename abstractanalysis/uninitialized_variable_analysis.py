import os
import sys
from binaryninja import *


# Load module and wait for initial binja analysis
inputfile = sys.argv[1]
bv = binaryview.BinaryViewType["Mach-O"].open(inputfile)
bv.update_analysis_and_wait()

def visit_instr(instr):
    if instr.operation == MediumLevelILOperation.MLIL_VAR_SSA:  # Read of variable
        if instr.index == 0:  # Not written
            if instr.src.type == ILVariableSourceType.StackVariableSourceType:
                if instr.src.identifier < 0:  # Local variables
                    print "Uninitialized stack variable reference at " + hex(instr.address)
    else:
        for operand in instr.operands:
            if isinstance(operand, MediumLevelILInstruction):
                visit_instr(operand)

for func in bv.functions:
    for block in func.medium_level_il.ssa_form:
        for instr in block:
            visit_instr(instr)



