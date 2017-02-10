from binaryninja import *
from collections import defaultdict
from copy import copy
import struct
import re

def read_value(bv, addr, size):
    fmt = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
    return struct.unpack(
        ('<' if bv.endianness is LittleEndian else '') + fmt[size],
        bv.read(addr, size)
    )[0]

def get_llil_basic_block(il, idx):
    for bb in il:
        if bb.start <= idx < bb.end:
            return bb
    return None

def handle_add(vtable, bv, expr, current_defs, defs, load_count):
    left = expr.left
    right = expr.right

    left_value = operation_handler[left.operation](
        vtable, bv, left, current_defs, defs, load_count
    )

    right_value = operation_handler[right.operation](
        vtable, bv, right, current_defs, defs, load_count
    )

    if None in (left_value, right_value):
        return None

    return left_value + right_value

def handle_load(vtable, bv, expr, current_defs, defs, load_count):
    load_count += 1

    if load_count == 2:
        return vtable

    addr = operation_handler[expr.src.operation](
        vtable, bv, expr.src, current_defs, defs, load_count
    )
    if addr is None:
        return

    # Read the value at the specified address.
    return read_value(bv, addr, expr.size)

def handle_reg(vtable, bv, expr, current_defs, defs, load_count):
    # Retrieve the LLIL expression that this register currently
    # represents.
    set_reg = current_defs.get(
        expr.src, None
    )
    if set_reg is None:
        return None

    return operation_handler[set_reg.src.operation](
        vtable, bv, set_reg.src,
        defs.get(set_reg.instr_index, {}), defs, load_count
    )

def handle_const(vtable, bv, expr, current_defs, defs, load_count):
    return expr.value

# This lets us handle expressions in a more generic way.
# operation handlers take the following parameters:
#   vtable (int): the address of the class's vtable in memory
#   bv (BinaryView): the BinaryView passed into the plugin callback
#   il (LowLevelILFunction): the function's LLIL object
#   expr (LowLevelILInstruction): the expression to handle
#   current_defs (dict): The current state of register definitions
#   defs (dict): The register state table for all instructions
#   load_count (int): The number of LLIL_LOAD operations encountered
operation_handler = defaultdict(lambda: (lambda *args: None))
operation_handler[LLIL_ADD] = handle_add
operation_handler[LLIL_REG] = handle_reg
operation_handler[LLIL_LOAD] = handle_load
operation_handler[LLIL_CONST] = handle_const

def preprocess_basic_block(bb):
    defs = {}
    current_defs = {}

    for instr in bb:
        defs[instr.instr_index] = copy(current_defs)

        if instr.operation == LLIL_SET_REG:
            current_defs[instr.dest] = instr

        elif instr.operation == LLIL_CALL:
            # wipe out previous definitions since we can't
            # guarantee the call didn't modify registers.
            current_defs.clear()

    return defs

def calculate_offset(vtable, bv, expr, current_defs, defs):
    return operation_handler[expr.operation](
        vtable, bv, expr, current_defs, defs, 0
    )

def find_constructor(bv):
    constructor_list = [(c.short_name, c.address) for c in bv.symbols.values()
                        if re.match(r'([A-Za-z0-9_]+)\:\:\1', c.short_name)]

    if not len(constructor_list):
        log_alert("No constructors found!")

    constructor = get_choice_input(
        'Choose a constructor', 'Constructors:',
        [x[0] for x in constructor_list]
    )

    if constructor is not None:
        return bv.get_function_at(
            bv.platform, constructor_list[constructor][1]
        )

    return None

def find_vtable(bv, function_il):
    source_function = function_il.source_function

    for bb in function_il:
        for il in bb:
            # If it's not a memory store, then it's not a vtable.
            if il.operation != LLIL_STORE:
                continue

            # vtable is referenced directly
            if (il.dest.operation, il.src.operation) == (LLIL_REG, LLIL_CONST):
                fp = read_value(bv, il.src.value, bv.address_size)

                if not bv.is_offset_executable(fp):
                    continue

                return il.src.value

            # vtable is first loaded into a register, then stored
            if (il.dest.operation, il.src.operation) == (LLIL_REG, LLIL_REG):
                reg_value = source_function.get_reg_value_at_low_level_il_instruction(
                    il.instr_index,
                    il.src.src
                )

                if reg_value.type == ConstantValue:
                    fp = read_value(bv, reg_value.value, bv.address_size)

                    if not bv.is_offset_executable(fp):
                        continue

                    return reg_value.value
    
    # Couldn't find a vtable.
    return None

def get_current_function(bv, address):
    return bv.get_basic_blocks_at(address)[0].function

def get_call_index(function, bv, addr):
    return function.get_low_level_il_at(bv.arch, addr)

def find_function_offset(vtable, bv, addr):
    function = get_current_function(bv, addr)

    call_il_idx = get_call_index(function, bv, addr)
    call_il = function.low_level_il[call_il_idx]

    if call_il.operation != LLIL_CALL:
        return

    bb = get_llil_basic_block(function.low_level_il, call_il_idx)

    defs = preprocess_basic_block(bb)

    return calculate_offset(
        vtable,
        bv,
        call_il.dest,
        defs.get(call_il_idx, {}),
        defs
    )


def navigate_to_virtual_function(bv, addr):
    constructor = find_constructor(bv)

    if constructor is None:
        return

    vtable = find_vtable(bv, constructor.low_level_il)

    if vtable is None:
        log_alert("Couldn't find vtable for class {}".format(class_name))
        return

    function_pointer = find_function_offset(vtable, bv, addr)

    if function_pointer is None:
        log_alert("Couldn't find vtable offset for this call!")
        return

    bv.file.navigate(bv.file.view, function_pointer)

PluginCommand.register_for_address(
    "Navigate to Virtual Function",
    "Navigate to the virtual function called by an indirect call, given the class name",
    navigate_to_virtual_function)