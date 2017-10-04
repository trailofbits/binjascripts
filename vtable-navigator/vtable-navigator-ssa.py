import re
import struct

from binaryninja import (Endianness, LowLevelILOperation, PluginCommand,
                         RegisterValueType, get_choice_input, log_alert)


class BNILVisitor(object):
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression):
        method_name = 'visit_{}'.format(expression.operation.name)
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            value = None
        return value


class VtableNavigatorVisitor(BNILVisitor):
    def __init__(self, **kw):
        super(VtableNavigatorVisitor, self).__init__(**kw)
        self.load_count = 0
        self.vtable = kw['vtable']
        self.bv = kw['bv']

    def visit_LLIL_CALL(self, expr):
        return self.visit(expr.dest)

    def visit_LLIL_ADD(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)
        if None in (left, right):
            return

        return left + right

    def visit_LLIL_LOAD(self, expr):
        self.load_count += 1

        if self.load_count == 2:
            return self.vtable

        return read_value(self.bv, self.visit(expr.src), expr.size)

    def visit_LLIL_REG(self, expr):
        instr_idx = expr.function.get_ssa_reg_definition(expr.ssa_form.src)
        if instr_idx is None:
            return None

        set_reg = expr.function[instr_idx]

        return self.visit(set_reg.src)

    def visit_LLIL_CONST(self, expr):
        return expr.constant


def read_value(bv, addr, size):

    fmt = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
    return struct.unpack(
        ('<' if bv.endianness is Endianness.LittleEndian else '') + fmt[size],
        bv.read(addr, size)
    )[0]


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
        return bv.get_function_at(constructor_list[constructor][1])

    return None


def find_vtable(bv, function_il):
    for bb in function_il:
        for il in bb:
            # If it's not a memory store, then it's not a vtable.
            if il.operation != LowLevelILOperation.LLIL_STORE:
                continue

            # vtable is referenced directly
            if (il.dest.operation == LowLevelILOperation.LLIL_REG and
                    il.src.operation == LowLevelILOperation.LLIL_CONST):
                fp = read_value(bv, il.src.constant, bv.address_size)

                if not bv.is_offset_executable(fp):
                    continue

                return il.src.constant

            # vtable is first loaded into a register, then stored
            if (il.dest.operation == LowLevelILOperation.LLIL_REG and
                    il.src.operation == LowLevelILOperation.LLIL_REG and
                    il.src.value.type == RegisterValueType.ConstantValue):
                fp = read_value(bv, il.src.value.value, bv.address_size)

                if not bv.is_offset_executable(fp):
                    continue

                return il.src.value.value

    # Couldn't find a vtable.
    return None


def get_current_function(bv, address):
    return bv.get_basic_blocks_at(address)[0].function


def find_function_offset(vtable, bv, addr):
    function = get_current_function(bv, addr)

    call_il = function.get_low_level_il_at(addr)

    return VtableNavigatorVisitor(bv=bv, vtable=vtable).visit(call_il)


def navigate_to_virtual_function(bv, addr):
    constructor = find_constructor(bv)

    if constructor is None:
        return

    vtable = find_vtable(bv, constructor.low_level_il)

    if vtable is None:
        log_alert(
            "Couldn't find vtable for {}".format(constructor.symbol.full_name)
        )
        return

    function_pointer = find_function_offset(vtable, bv, addr)

    if function_pointer is None:
        log_alert("Couldn't find vtable offset for this call!")
        return

    bv.file.navigate(bv.file.view, function_pointer)


PluginCommand.register_for_address(
    "Navigate to Virtual Function (SSA)",
    ("Navigate to the virtual function called by "
        "an indirect call, given the class name"),
    navigate_to_virtual_function)
