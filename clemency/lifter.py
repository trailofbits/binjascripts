from binaryninja import *

conditions = {}
conditions[0] = LowLevelILFlagCondition.LLFC_NE
conditions[1] = LowLevelILFlagCondition.LLFC_E
conditions[2] = LowLevelILFlagCondition.LLFC_ULT
conditions[3] = LowLevelILFlagCondition.LLFC_ULE
conditions[4] = LowLevelILFlagCondition.LLFC_UGT
conditions[5] = LowLevelILFlagCondition.LLFC_UGE
conditions[6] = LowLevelILFlagCondition.LLFC_NO
conditions[7] = LowLevelILFlagCondition.LLFC_O
conditions[8] = LowLevelILFlagCondition.LLFC_POS
conditions[9] = LowLevelILFlagCondition.LLFC_NEG
conditions[10] = LowLevelILFlagCondition.LLFC_SLT
conditions[11] = LowLevelILFlagCondition.LLFC_SLE
conditions[12] = LowLevelILFlagCondition.LLFC_SGT
conditions[13] = LowLevelILFlagCondition.LLFC_SGE
conditions[15] = None

def get_next_reg(reg):
    try:
        idx = int(reg[1:])
    except ValueError:
        if reg == 'st':
            idx = 29
        elif reg == 'ra':
            idx = 30
        elif reg == 'pc':
            idx = 31

    next_idx = (idx + 1) % 32

    if next_idx == 29:
        return 'st'
    if next_idx == 30:
        return 'ra'
    if next_idx == 31:
        return 'pc'

    return 'r{}'.format(next_idx)

class Lifter(object):
    @staticmethod
    def lift(addr, opcode, operands, length, il):
        if hasattr(Lifter, 'lift_' + opcode):
            getattr(Lifter, 'lift_'+opcode)(addr, length, il, *operands)
        else:
            il.append(il.unimplemented())

    @staticmethod
    def lift_B(addr, length, il, condition, code, offset):
        dest = il.const_pointer(4, offset)
        t = il.get_label_for_address(
            Architecture['clemency'],
            offset
        )

        if t is None:
            # t is an address not in the current function scope.
            t = LowLevelILLabel()
            indirect = True
        else:
            indirect = False
        
        if code == '':
            if indirect:
                il.append(il.jump(dest))
            else:
                il.append(il.goto(t))

        else:
            cond = il.flag_condition(conditions[condition])

            f_label_found = True

            f = il.get_label_for_address(
                Architecture['clemency'],
                addr + length
            )

            if f is None:
                f = LowLevelILLabel()
                f_label_found = False

            il.append(il.if_expr(cond, t, f))

            if indirect:
                # If the destination is not in the current function,
                # then a jump, rather than a goto, needs to be added to
                # the IL.
                il.mark_label(t)
                il.append(il.jump(dest))

            if not f_label_found:
                il.mark_label(f)

    @staticmethod
    def lift_CAR(addr, length, il, loc):
        il.append(il.set_reg(4, 'ra', il.const_pointer(4, addr+length)))
        il.append(il.call(il.const_pointer(4, loc)))

    @staticmethod
    def lift_HT(addr, length, il):
        il.append(il.no_ret())

    @staticmethod
    def lift_MH(addr, length, il, rA, imm):
        il.append(
            il.set_reg(
                4, 
                rA,
                il.or_expr(
                    4,
                    il.const(4, imm << 10),
                    il.and_expr(4, il.reg(4, rA), il.const(4, 0x3ff))
                )
            )
        )

    @staticmethod
    def lift_ML(addr, length, il, rA, imm):
        il.append(il.set_reg(4, rA, il.const(4, imm)))

    @staticmethod
    def lift_OR(addr, length, il, rA, rB, rC, uf):
        if uf:
            or_op = il.or_expr(4, il.reg(4, rB), il.reg(4, rC), flags='*')
        else:
            or_op = il.or_expr(4, il.reg(4, rB), il.reg(4, rC))
        il.append(il.set_reg(4, rA, or_op))

    @staticmethod
    def lift_ORI(addr, length, il, rA, rB, imm, uf):
        if uf:
            or_op = il.or_expr(4, il.reg(4, rB), il.const(4, imm*2), flags='*')
        else:
            or_op = il.or_expr(4, il.reg(4, rB), il.const(4, imm*2))
        il.append(il.set_reg(4, rA, or_op))

    @staticmethod
    def lift_RE(addr, length, il):
        il.append(il.ret(il.reg(4, 'ra')))

    @staticmethod
    def lift_SBI(addr, length, il, rA, rB, imm, uf):
        imm_expr = il.const(4, imm*2)
        if uf:
            sub_op = il.sub(4, il.reg(4, rB), imm_expr, flags='*')
        else:
            sub_op = il.sub(4, il.reg(4, rB), imm_expr)
        il.append(il.set_reg(4, rA, sub_op))

    @staticmethod
    def lift_STT(addr, length, il, rA, rB, reg_count, m, offset):
        temp_reg = LLIL_TEMP(1)
        mem_location_reg = LLIL_TEMP(2)

        # Temp = rB
        il.append(il.set_reg(4, temp_reg, il.reg(4, rB)))

        # CurCount = RegCount
        cur_count = reg_count

        # if Mode is 2 then
        #   Temp = Temp - (CurCount * 3)
        if m == 'D':
            imm_expr = il.const(4, reg_count  * 3 * 2)
            il.append(il.set_reg(4, temp_reg, il.sub(4, il.reg(4, rB), imm_expr)))

        # MemLocation = (Temp + Offset)
        il.append(il.set_reg(4, mem_location_reg, il.add(4, il.reg(4, temp_reg), il.const(4, offset))))

        # While CurCount is not 0
        while cur_count:
            # Memory[MemLocation] = (Registers[StartReg] >> 9) & 0x1ff
            il.append(
                il.store(
                    2,
                    il.reg(4, mem_location_reg),
                    il.and_expr(
                        2,
                        il.logical_shift_right(4, il.reg(4, rA[0]), il.const(4, 9)),
                        il.const(2, 0x1ff)
                    )
                )
            )

            # MemLocation = MemLocation + 1
            il.append(il.set_reg(4, mem_location_reg, il.add(4, il.reg(4, mem_location_reg), il.const(4, 2))))

            # Memory[MemLocation] = (Registers[StartReg] >> 18) & 0x1ff
            il.append(
                il.store(
                    2,
                    il.reg(4, mem_location_reg),
                    il.and_expr(
                        2,
                        il.logical_shift_right(4, il.reg(4, rA[0]), il.const(4, 18)),
                        il.const(2, 0x1ff)
                    )
                )
            )

            # MemLocation = MemLocation + 1
            il.append(il.set_reg(4, mem_location_reg, il.add(4, il.reg(4, mem_location_reg), il.const(4, 2))))

            # Memory[MemLocation] = Registers[StartReg] & 0x1ff
            il.append(
                il.store(
                    2,
                    il.reg(4, mem_location_reg),
                    il.and_expr(
                        2,
                        il.reg(4, rA[0]),
                        il.const(2, 0x1ff)
                    )
                )
            )

            # MemLocation = MemLocation + 1
            il.append(il.set_reg(4, mem_location_reg, il.add(4, il.reg(4, mem_location_reg), il.const(4, 2))))

            rA = rA[1:]

            cur_count -= 1

        if m == 'I':
            il.append(il.set_reg(4, rB, il.add(4, il.reg(4, rB), il.const(4, reg_count * 3))))
        if m == 'D':
            il.append(il.set_reg(4, rB, il.reg(4, temp_reg)))
