# Navigating to a Virtual Function based on an Indirect Call

import struct
import re

from binaryninja import *

def find_vtable(bv, function_il):
    source_function = function_il.source_function

    for bb in function_il:
        for il in bb:
            # vtable is referenced directly
            if (il.operation == LLIL_STORE and
                il.dest.operation == LLIL_REG and
                il.src.operation == LLIL_CONST):
                fp = struct.unpack(
                    '<Q' if bv.address_size == 8 else '<L',
                    bv.read(il.src.value, bv.address_size)
                )[0]

                if not bv.is_offset_executable(fp):
                    continue

                return il.src.value

            # vtable is first loaded into a register, then stored
            if (il.operation == LLIL_STORE and
                il.dest.operation == LLIL_REG and
                il.src.operation == LLIL_REG):
                reg_value = source_function.get_reg_value_at_low_level_il_instruction(
                    il.instr_index,
                    il.src.src
                )

                if reg_value.type == ConstantValue:
                    fp = struct.unpack(
                        '<Q' if bv.address_size == 8 else '<L',
                        bv.read(reg_value.value, bv.address_size)
                    )[0]

                    if not bv.is_offset_executable(fp):
                        continue

                    return reg_value.value
    return None

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

def get_current_function(bv, address):
    return bv.get_basic_blocks_at(address)[0].function

def find_function_offset(bv, address):
    current_function = get_current_function(bv, address)
    current_function_il = current_function.low_level_il
    current_instruction = current_function_il[
        current_function.get_low_level_il_at(bv.arch, address)
    ]

    # make sure it's a call instruction
    if current_instruction.operation != LLIL_CALL:
        log_alert("This isn't a call instruction")
        return

    # call <register>
    if current_instruction.dest.operation == LLIL_REG:
        call_reg = current_instruction.dest.src

        offset = None

        # step backwards to find this register being set to an offset
        for idx in range(current_instruction.instr_index, -1, -1):
            il = current_function_il[idx]

            # find instances of the call register being changed
            if (il.operation != LLIL_SET_REG or
                il.dest != call_reg):
                continue

            # is it something like mov reg, [reg]?
            if (il.src.operation == LLIL_LOAD and
                il.src.src.operation == LLIL_REG and
                offset is None):
                offset = 0
                # continue on, to see if there is an offset add
                continue

            # mov reg, [register+offset]?
            if (il.src.operation == LLIL_LOAD and
                il.src.src.operation == LLIL_ADD and
                il.src.src.right.operation == LLIL_CONST):
                    offset = il.src.src.right.value
                    break

            # already found a load with no offset, now finding offset
            if (offset == 0 and
                il.src.operation == LLIL_ADD and
                il.src.right.operation == LLIL_CONST):
                offset = il.src.right.value
                break

            # to keep from accidentally finding other stuff, bail if
            # any other register set happens
            break

    return offset

def navigate_to_virtual_function(bv, address):
    constructor = find_constructor(bv)

    if constructor is None:
        return

    vtable = find_vtable(bv, constructor.low_level_il)

    if vtable is None:
        log_alert("Couldn't find vtable for class {}".format(class_name))
        return

    offset = find_function_offset(bv, address)

    if offset is None:
        log_alert("Couldn't find vtable offset for this call!")
        return

    function_pointer = struct.unpack(
        '<Q' if bv.address_size == 8 else '<L',
        bv.read(vtable+offset, bv.address_size)
    )[0]

    bv.file.navigate(bv.file.view, function_pointer)


PluginCommand.register_for_address(
    'Navigate to Virtual Function',
    'Navigate to the virtual function called by an indirect call, given the class name',
    navigate_to_virtual_function
)