#!/usr/bin/env python

from binaryninja import *
import struct

from enum import Enum
import itertools
from collections import defaultdict

from .lifter import Lifter, get_next_reg

class InsnType(Enum):
    Load = 0
    Store = 1
    Mov = 2
    Alu = 3
    ConditionalBranch = 4
    UnconditionalBranch = 5
    Return = 6
    Unimplemented = 99

codes = {}
codes[0] = 'NE/NZ'
codes[1] = 'E/Z'
codes[2] = 'LT'
codes[3] = 'LTE'
codes[4] = 'GT'
codes[5] = 'GTE'
codes[6] = 'NO'
codes[7] = 'O'
codes[8] = 'NS'
codes[9] = 'S'
codes[10] = 'SLT'
codes[11] = 'SLTE'
codes[12] = 'SGT'
codes[13] = 'SGTE'
codes[15] = ''



def neg(v):
    return ~(v - 1) & 0x1ffff

def tok_T(opcode, *args):
    print opcode
    return [InstructionTextToken(InstructionTextTokenType.TextToken, opcode)]

tok = defaultdict(lambda: tok_T)
tok['HT'] = tok_T

def tok_R(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            ]

    return tokens
tok['EI'] = tok_R

def tokLDT(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, args[3]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ' ')
    ]

    if isinstance(args[0], list):
        for reg in args[0]:
            tokens += [
                InstructionTextToken(InstructionTextTokenType.RegisterToken, reg),
                InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            ]
    else:
        tokens += [
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
        ]

    tokens += [
        InstructionTextToken(InstructionTextTokenType.TextToken, "["),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, args[1]),
        InstructionTextToken(InstructionTextTokenType.TextToken, " + "),
        InstructionTextToken(InstructionTextTokenType.IntegerToken, "{:#x}".format(args[4]), args[4]),
        InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
        InstructionTextToken(InstructionTextTokenType.IntegerToken, "{:#x}".format(args[2]), args[2]),
        InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
    ]

    return tokens
tok['LDT'] = tokLDT
tok['STT'] = tokLDT
tok['STS'] = tokLDT
tok['STW'] = tokLDT
tok['LDS'] = tokLDT
tok['LDW'] = tokLDT

def tok_FRRR(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, args[3]),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[1]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[2]),
            ]

    return tokens
tok['AD'] = tok_FRRR
tok['ADC'] = tok_FRRR
tok['ADCM'] = tok_FRRR
tok['ADF'] = tok_FRRR
tok['ADFM'] = tok_FRRR
tok['ADM'] = tok_FRRR

tok['SB'] = tok_FRRR
tok['SBC'] = tok_FRRR
tok['SBCM'] = tok_FRRR
tok['SBF'] = tok_FRRR
tok['SBFM'] = tok_FRRR
tok['SBM'] = tok_FRRR

tok['MU'] = tok_FRRR
tok['MUF'] = tok_FRRR
tok['MUFM'] = tok_FRRR
tok['MUM'] = tok_FRRR
tok['MUS'] = tok_FRRR
tok['MUSM'] = tok_FRRR

tok['DV'] = tok_FRRR
tok['DVF'] = tok_FRRR
tok['DVFM'] = tok_FRRR
tok['DVM'] = tok_FRRR
tok['DVS'] = tok_FRRR
tok['DVSM'] = tok_FRRR

tok['MD'] = tok_FRRR
tok['MDF'] = tok_FRRR
tok['MDFM'] = tok_FRRR
tok['MDM'] = tok_FRRR
tok['MDS'] = tok_FRRR
tok['MDSM'] = tok_FRRR

tok['OR'] = tok_FRRR
tok['RL'] = tok_FRRR
tok['RR'] = tok_FRRR
tok['AN'] = tok_FRRR
tok['XR'] = tok_FRRR

tok['SR'] = tok_FRRR
tok['SL'] = tok_FRRR
tok['SA'] = tok_FRRR
tok['SRM'] = tok_FRRR
tok['SLM'] = tok_FRRR
tok['SAM'] = tok_FRRR

def tok_RRR(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[1]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[2]),
            ]

    return tokens
tok['DMT'] = tok_RRR

def tok_RRT(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[1]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.TextToken, args[2]),
            ]

    return tokens
tok['SMP'] = tok_RRT

def tok_RR(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[1]),
            ]

    return tokens
tok['CM'] = tok_RR
tok['SES'] = tok_RR
tok['ZES'] = tok_RR
tok['ZEW'] = tok_RR
tok['SEW'] = tok_RR
tok['RMP'] = tok_RR

def tok_FRR(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, args[2]),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[1]),
            ]

    return tokens
tok['BF'] = tok_FRR

def tok_RI(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, "{:#x}".format(args[1]), args[1]),
            ]
    return tokens
tok['MH'] = tok_RI
tok['ML'] = tok_RI
tok['MS'] = tok_RI
tok['CMI'] = tok_RI

def tok_FRRI(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, args[3]),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[0]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, args[1]),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, "{:#x}".format(args[2]), args[2]),
            ]
    return tokens
tok['ADI'] = tok_FRRI
tok['SBI'] = tok_FRRI
tok['ORI'] = tok_FRRI
tok['RLI'] = tok_FRRI
tok['RRI'] = tok_FRRI
tok['ANI'] = tok_FRRI
tok['XRI'] = tok_FRRI
tok['SAI'] = tok_FRRI
tok['SLI'] = tok_FRRI

def tok_A(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "{:#x}".format(args[0]), args[0]),
            ]
    return tokens
tok['CAR'] = tok_A
tok['CAA'] = tok_A

def tokBranch(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, "."),
            InstructionTextToken(InstructionTextTokenType.TextToken, args[1]),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "{:#x}".format(args[2]), args[2]),
            ]
    return tokens
tok['B'] = tokBranch

def tokBRA(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "{:#x}".format(args[0]), args[0]),
            ]
    return tokens
tok['BRA'] = tokBRA

def tokCR(opcode, *args):
    tokens = [
            InstructionTextToken(InstructionTextTokenType.TextToken, opcode),
            InstructionTextToken(InstructionTextTokenType.TextToken, "."),
            InstructionTextToken(InstructionTextTokenType.TextToken, args[1]),
            InstructionTextToken(InstructionTextTokenType.TextToken, " "),
            InstructionTextToken(InstructionTextTokenType.TextToken, args[2]),
            ]
    return tokens


tok['CR'] = tokCR

class Clemency(Architecture):
    name = 'clemency'
    address_size = 4
    default_int_size = 4

    regs = { 
            'r0' : RegisterInfo('r0', default_int_size),
            'r1' : RegisterInfo('r1', default_int_size),
            'r2' : RegisterInfo('r2', default_int_size),
            'r3' : RegisterInfo('r3', default_int_size),
            'r4' : RegisterInfo('r4', default_int_size),
            'r5' : RegisterInfo('r5', default_int_size),
            'r6' : RegisterInfo('r6', default_int_size),
            'r7' : RegisterInfo('r7', default_int_size),
            'r8' : RegisterInfo('r8', default_int_size),
            'r9' : RegisterInfo('r9', default_int_size),
            'r10' : RegisterInfo('r10', default_int_size),
            'r11' : RegisterInfo('r11', default_int_size),
            'r12' : RegisterInfo('r12', default_int_size),
            'r13' : RegisterInfo('r13', default_int_size),
            'r14' : RegisterInfo('r14', default_int_size),
            'r15' : RegisterInfo('r15', default_int_size),
            'r16' : RegisterInfo('r16', default_int_size),
            'r17' : RegisterInfo('r17', default_int_size),
            'r18' : RegisterInfo('r18', default_int_size),
            'r19' : RegisterInfo('r19', default_int_size),
            'r20' : RegisterInfo('r20', default_int_size),
            'r21' : RegisterInfo('r21', default_int_size),
            'r22' : RegisterInfo('r22', default_int_size),
            'r23' : RegisterInfo('r23', default_int_size),
            'r24' : RegisterInfo('r24', default_int_size),
            'r25' : RegisterInfo('r25', default_int_size),
            'r26' : RegisterInfo('r26', default_int_size),
            'r27' : RegisterInfo('r27', default_int_size),
            'r28' : RegisterInfo('r28', default_int_size),
            'st' : RegisterInfo('st', default_int_size),
            'ra' : RegisterInfo('ra', default_int_size),
            'pc' : RegisterInfo('pc', default_int_size),
            }

    stack_pointer = 'st'
    link_reg = 'ra'

    flags = ['z', 'c', 'o', 's']

    flag_write_types = ['*']

    flag_written_by_flag_write_type = {
        '*': ['z', 'c', 'o', 's']
    }

    def decode_register(self, r):
        if r <= 28:
            return 'r{}'.format(r)
        elif r == 29:
            return 'st'
        elif r == 30:
            return 'ra'
        
        return 'pc'

    def decode_opcode(self, addr, data):
        e = struct.unpack("H"*(len(data)/2), data)
        a = map(lambda i: '{:09b}'.format(i), e)
        
        if len(a) == 2:
            insn = a[1] + a[0]
        else:
            insn = a[1] + a[0] + a[2]
            insn3 = insn

        if len(a) >= 4:
            insn4 = insn + a[3]
        if len(a) >= 5:
            insn5 = insn + a[4] + a[3]
        if len(a) >= 6:
            insn6 = insn + a[4] + a[3] + a[5]

        opcode = "UNIMPLEMENTED {}".format(insn)
        operands = []
        insn_length = 2

        if insn.startswith('0000000') and insn[22:26] == '0000':
            opcode = "AD"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0100000') and insn[22:26] == '0000':
            opcode = "ADC"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0100000') and insn[24:26] == '01':
            opcode = "ADCI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0100010') and insn[24:26] == '01':
            opcode = "ADCIM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0100010') and insn[22:26] == '0000':
            opcode = "ADCM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000001') and insn[22:26] == '0000':
            opcode = "ADF"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000011') and insn[22:26] == '0000':
            opcode = "ADFM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000000') and insn[24:26] == '01':
            opcode = "ADI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000010') and insn[24:26] == '01':
            opcode = "ADIM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000010') and insn[22:26] == '0000':
            opcode = "ADM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010100') and insn[22:26] == '0000':
            opcode = "AN"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010100') and insn[24:26] == '01':
            opcode = "ANI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010110') and insn[22:26] == '0000':
            opcode = "ANM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('110000'):
            opcode = 'B'

            condition = int(insn3[6:10], 2)
            offset = int(insn3[10:27], 2)

            if insn3[10] == '1': #negative
                loc = addr - (neg(offset) * 2)
            else:
                loc = addr + (offset * 2)

            operands.append(condition)
            operands.append(codes[condition])
            operands.append(loc)

            insn_length = 3
        elif insn.startswith('101001100'):
            opcode = "BF"

            rA = int(insn3[9:14], 2)
            rB = int(insn3[14:18], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101001110'):
            opcode = "BFM"

            rA = int(insn3[9:14], 2)
            rB = int(insn3[14:18], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('110010'):
            opcode = 'BR'

            condition = int(insn3[6:10], 2)
            rA = int(insn3[10:15], 2)

            operands.append(condition)
            operands.append(codes[condition])
            operands.append(self.decode_register(rA))

            insn_length = 3
        elif insn.startswith('111000100'):
            opcode = 'BRA'

            loc = int(insn4[9:36], 2) * 2

            operands.append(loc)

            insn_length = 4
        elif insn.startswith('111000100'):
            opcode = 'BRR'

            offset = int(insn4[9:36], 2)
            if insn3[10] == '1': #negative
                loc = addr - (~(offset - 1) & 0x7FFFFFF)
            else:
                loc = addr + (offset * 2)

            operands.append(loc)

            insn_length = 4
        elif insn.startswith('110101'):
            opcode = 'C'

            condition = int(insn3[6:10], 2)

            loc = int(insn4[10:27], 2)
            if insn4[9] == '1':
                loc = addr - (neg(loc) * 2)
            else:
                loc = addr + (loc * 2)

            operands.append(condition)
            operands.append(codes[condition])
            operands.append(loc)

            insn_length = 3
        elif insn.startswith('111001100'):
            opcode = 'CAA'

            loc = int(insn4[9:36], 2)
            if insn4[9] == '1':
                loc = addr - (neg(loc) * 2)
            else:
                loc = addr + (loc * 2)

            operands.append(loc)

            insn_length = 4
        elif insn.startswith('111001000'):
            opcode = 'CAR'

            loc = int(insn4[9:36], 2)
            if insn4[9] == '1':
                loc = addr - (neg(loc) * 2)
            else:
                loc = addr + (loc * 2)

            operands.append(loc)

            insn_length = 4
        elif insn.startswith('10111000'):
            opcode = "CM"

            rA = int(insn[8:13], 2)
            rB = int(insn[13:18], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 2
        elif insn.startswith('10111010'):
            opcode = "CMF"

            rA = int(insn[8:13], 2)
            rB = int(insn[13:18], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 2
        elif insn.startswith('10111110'):
            opcode = "CMFM"

            rA = int(insn[8:13], 2)
            rB = int(insn[13:18], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 2
        elif insn.startswith('10111001'):
            opcode = "CMI"

            rA = int(insn3[8:13], 2)
            imm = int(insn3[13:27], 2)

            operands.append(self.decode_register(rA))
            operands.append(imm)

            insn_length = 3
        elif insn.startswith('10111101'):
            opcode = "CMIM"

            rA = int(insn3[8:13], 2)
            imm = int(insn3[13:27], 2)

            operands.append(self.decode_register(rA))
            operands.append(imm)

            insn_length = 3
        elif insn.startswith('110111'):
            opcode = 'CR'

            condition = int(insn3[6:10], 2)

            rA = int(insn3[10:14], 2)

            operands.append(condition)
            operands.append(codes[condition])
            operands.append(self.decode_register(rA))

            insn_length = 2
        elif insn.startswith('111111111111111111'):
            opcode = 'DBRK'
            insn_length = 2
        elif insn.startswith('101000000101'):
            opcode = 'DI'

            rA = int(insn[12:17], 2)

            operands.append(self.decode_register(rA))

            insn_length = 2
        elif insn.startswith('0110100'):
            opcode = "DMT"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))

            insn_length = 3
        elif insn.startswith('0001100'):
            opcode = "DV"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001101'):
            opcode = "DVF"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001111'):
            opcode = "DVFM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001100') and insn[24:26] == '01':
            opcode = "DVI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001110') and insn[24:26] == '01':
            opcode = "DVIM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001100') and insn[24:26] == '11':
            opcode = "DVIS"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)

            if insn3[17] == '1':
                imm = -(~(imm - 1) & 0x7F)

            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001110') and insn[24:26] == '11':
            opcode = "DVISM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)

            if insn3[17] == '1':
                imm = -(~(imm - 1) & 0x7F)

            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001110') and insn[22:26] == '0000':
            opcode = "DVM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001100') and insn[22:26] == '0010':
            opcode = "DVS"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001110') and insn[22:26] == '0010':
            opcode = "DVSM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101000000100'):
            opcode = 'EI'

            rA = int(insn[12:17], 2)

            operands.append(self.decode_register(rA))

            insn_length = 2
        elif insn.startswith('101000101'):
            opcode = 'FTI'

            rA = int(insn[9:13], 2)
            rB = int(insn[13:19], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3
        elif insn.startswith('101000101'):
            opcode = 'FTIM'

            rA = int(insn[9:13], 2)
            rB = int(insn[13:19], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3
        elif insn.startswith('101000000011000000'):
            opcode = 'HT'
            insn_length = 2
        elif insn.startswith('101000000001000000'):
            opcode = 'IR'
            insn_length = 2
        elif insn.startswith('101000100'):
            opcode = 'ITF'

            rA = int(insn[9:13], 2)
            rB = int(insn[13:19], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3
        elif insn.startswith('101000110'):
            opcode = 'ITFM'

            rA = int(insn[9:13], 2)
            rB = int(insn[13:19], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3
        elif insn.startswith('1010100'):
            opcode = "LDS"

            rA = int(insn6[7:12], 2)
            rB = int(insn6[12:17], 2)
            register_count = int(insn6[17:22], 2)+1
            adjust_rB = int(insn6[22:24], 2)
            mem_offset = insn6[24:51]
            mem_offset = int(mem_offset, 2)

            if insn6[24] == '1': #negative
                mem_offset = -(~(mem_offset - 1) & 0x7FFFFFF)

            m = ""
            if adjust_rB == 1:
                m = "I"
            elif adjust_rB == 2:
                m = "D"

            regs = []
            current_reg = self.decode_register(rA)
            for i in range(register_count):
                regs.append(current_reg)
                current_reg = get_next_reg(current_reg)

            operands.append(regs)
            operands.append(self.decode_register(rB))
            operands.append(register_count)
            operands.append(m)
            operands.append(mem_offset)

            insn_length = 6
        elif insn.startswith('1010110'):
            # ldt load tri
            opcode = "LDT"

            rA = int(insn6[7:12], 2)
            rB = int(insn6[12:17], 2)
            register_count = int(insn6[17:22], 2)+1
            adjust_rB = int(insn6[22:24], 2)
            mem_offset = insn6[24:51]
            #mem_offset = int(mem_offset[9:18] + mem_offset[:9] + mem_offset[18:], 2)
            mem_offset = int(mem_offset, 2)

            m = ""
            if adjust_rB == 1:
                m = "I"
            elif adjust_rB == 2:
                m = "D"

            regs = []
            current_reg = self.decode_register(rA)
            for i in range(register_count):
                regs.append(current_reg)
                current_reg = get_next_reg(current_reg)

            operands.append(regs)
            operands.append(self.decode_register(rB))
            operands.append(register_count)
            operands.append(m)
            operands.append(mem_offset)

            insn_length = 6
        elif insn.startswith('1010101'):
            opcode = "LDW"

            rA = int(insn6[7:12], 2)
            rB = int(insn6[12:17], 2)
            register_count = int(insn6[17:22], 2)+1
            adjust_rB = int(insn6[22:24], 2)
            mem_offset = insn6[24:51]
            mem_offset = int(mem_offset[9:18]+mem_offset[:9]+mem_offset[18:], 2)

            m = ""
            if adjust_rB == 1:
                m = "I"
            elif adjust_rB == 2:
                m = "D"

            regs = []
            current_reg = self.decode_register(rA)
            for i in range(register_count):
                regs.append(current_reg)
                current_reg = get_next_reg(current_reg)

            operands.append(regs)
            operands.append(self.decode_register(rB))
            operands.append(register_count)
            operands.append(m)
            operands.append(mem_offset)

            insn_length = 6
        elif insn.startswith('0010000'):
            opcode = "MD"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010001'):
            opcode = "MDF"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010011'):
            opcode = "MDFM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010000') and insn[24:26] == '01':
            opcode = "MDI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010010') and insn[24:26] == '01':
            opcode = "MDIM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010000') and insn[24:26] == '11':
            opcode = "MDIS"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)

            if insn3[17] == '1':
                imm = -(~(imm - 1) & 0x7F)

            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010010') and insn[24:26] == '11':
            opcode = "MDISM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)

            if insn3[17] == '1':
                imm = -(~(imm - 1) & 0x7F)

            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010010') and insn[22:26] == '0000':
            opcode = "MDM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010000') and insn[22:26] == '0010':
            opcode = "MDS"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0010010') and insn[22:26] == '0010':
            opcode = "MDSM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('10001'):
            opcode = "MH"

            rA = int(insn3[5:10], 2)
            imm = int(insn3[10:27], 2)

            operands.append(self.decode_register(rA))
            operands.append(imm)

            insn_length = 3
        elif insn.startswith('10010'):
            opcode = "ML"

            rA = int(insn3[5:10], 2)
            imm = int(insn3[10:27], 2)

            operands.append(self.decode_register(rA))
            operands.append(imm)

            insn_length = 3
        elif insn.startswith('10011'):
            opcode = "MS"

            rA = int(insn3[5:10], 2)
            imm = int(insn3[10:27], 2)
            if insn3[10] == '1': #negative
                imm = -(~(imm - 1) & 0x1FFFF)

            operands.append(self.decode_register(rA))
            operands.append(imm)

            insn_length = 3
        elif insn.startswith('0001000'):
            opcode = "MU"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001001'):
            opcode = "MUF"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001011'):
            opcode = "MUFM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001000') and insn[24:26] == '01':
            opcode = "MUI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001010') and insn[24:26] == '01':
            opcode = "MUIM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001000') and insn[24:26] == '11':
            opcode = "MUIS"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)

            if insn3[17] == '1':
                imm = -(~(imm - 1) & 0x7F)

            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001010') and insn[24:26] == '11':
            opcode = "MUISM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)

            if insn3[17] == '1':
                imm = -(~(imm - 1) & 0x7F)

            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001010') and insn[22:26] == '0000':
            opcode = "MUM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001000') and insn[22:26] == '0010':
            opcode = "MUS"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0001010') and insn[22:26] == '0010':
            opcode = "MUSM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101001100'):
            opcode = "NG"

            rA = int(insn3[9:14], 2)
            rB = int(insn3[14:19], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101001101'):
            opcode = "NGF"

            rA = int(insn3[9:14], 2)
            rB = int(insn3[14:19], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101001111'):
            opcode = "NGFM"

            rA = int(insn3[9:14], 2)
            rB = int(insn3[14:19], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101001110'):
            opcode = "NGM"

            rA = int(insn3[9:14], 2)
            rB = int(insn3[14:19], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101001100'):
            opcode = "NT"

            rA = int(insn3[9:14], 2)
            rB = int(insn3[14:19], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101001110'):
            opcode = "NTM"

            rA = int(insn3[9:14], 2)
            rB = int(insn3[14:19], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0011000') and insn[22:26] == '0000':
            opcode = "OR"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0011000') and insn[24:26] == '01':
            opcode = "ORI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0011010') and insn[22:26] == '0000':
            opcode = "ORM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101000000000000000'):
            opcode = 'RE'
            insn_length = 2
        elif insn.startswith('101000001100'):
            opcode = 'RF'

            rA = int(insn3[12:17], 2)

            operands.append(self.decode_register(rA))

            insn_length = 2
        elif insn.startswith('0110000'):
            opcode = 'RL'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('1000000'):
            opcode = 'RLI'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('1000010'):
            opcode = 'RLIM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0110000'):
            opcode = 'RLM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('1010010') and insn[17] == '0':
            opcode = "RMP"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3
        elif insn.startswith('101001100'):
            opcode = "RND"

            rA = int(insn3[9:14], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101001110'):
            opcode = "RNDM"

            rA = int(insn3[9:14], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0110001'):
            opcode = 'RR'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('1000001'):
            opcode = 'RRI'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('1000011'):
            opcode = 'RRIM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0110011'):
            opcode = 'RRM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0101101'):
            opcode = 'SA'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0111101'):
            opcode = 'SAI'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0111111'):
            opcode = 'SAIM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0101111'):
            opcode = 'SAM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000100') and insn[22:26] == '0000':
            opcode = "SB"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0100100') and insn[22:26] == '0000':
            opcode = "SBC"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0100100') and insn[24:26] == '01':
            opcode = "SBCI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0100110') and insn[24:26] == '01':
            opcode = "SBCIM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0100110') and insn[22:26] == '0000':
            opcode = "SBCM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000101') and insn[22:26] == '0000':
            opcode = "SBF"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000111') and insn[22:26] == '0000':
            opcode = "SBFM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000100') and insn[24:26] == '01':
            opcode = "SBI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000110') and insn[24:26] == '01':
            opcode = "SBIM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0000110') and insn[22:26] == '0000':
            opcode = "SBM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101000000111'):
            opcode = "SES"

            rA = int(insn3[12:17], 2)
            rB = int(insn3[17:22], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3
        elif insn.startswith('101000001000'):
            opcode = "SEW"

            rA = int(insn3[12:17], 2)
            rB = int(insn3[17:22], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3
        elif insn.startswith('101000001011'):
            opcode = "SF"

            rA = int(insn3[12:17], 2)

            operands.append(self.decode_register(rA))

            insn_length = 2
        elif insn.startswith('0101000'):
            opcode = 'SL'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0111000'):
            opcode = 'SLI'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0111010'):
            opcode = 'SLIM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0101010'):
            opcode = 'SLM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('1010010') and insn[17] == '1':
            opcode = "SMP"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            flags = int(insn3[18:20], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            
            if flags == 0:
                F = '---'
            elif flags == 1:
                F = 'R--'
            elif flags == 2:
                F = 'RW-'
            elif flags == 3:
                F = 'R-X'

            operands.append(F)

            insn_length = 3
        elif insn.startswith('0101001'):
            opcode = 'SR'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0111001'):
            opcode = 'SRI'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0111011'):
            opcode = 'SRIM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0101011'):
            opcode = 'SRM'

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('1011000'):
            opcode = "STS"

            rA = int(insn6[7:12], 2)
            rB = int(insn6[12:17], 2)
            register_count = int(insn6[17:22], 2)+1
            adjust_rB = int(insn6[22:24], 2)
            mem_offset = insn6[24:51]
            mem_offset = int(mem_offset, 2)

            if insn6[24] == '1': #negative
                mem_offset = -(~(mem_offset - 1) & 0x7FFFFFF)

            m = ""
            if adjust_rB == 1:
                m = "I"
            elif adjust_rB == 2:
                m = "D"
            
            regs = []
            current_reg = self.decode_register(rA)
            for i in range(register_count):
                regs.append(current_reg)
                current_reg = get_next_reg(current_reg)

            operands.append(regs)
            operands.append(self.decode_register(rB))
            operands.append(register_count)
            operands.append(m)
            operands.append(mem_offset)

            insn_length = 6
        elif insn.startswith('1011010'):
            opcode = "STT"

            rA = int(insn6[7:12], 2)
            rB = int(insn6[12:17], 2)
            register_count = int(insn6[17:22], 2)+1
            adjust_rB = int(insn6[22:24], 2)
            mem_offset = insn6[24:51]
            #mem_offset = int(mem_offset[9:18] + mem_offset[:9] + mem_offset[18:], 2)
            mem_offset = int(mem_offset, 2)

            m = ""
            if adjust_rB == 1:
                m = "I"
            elif adjust_rB == 2:
                m = "D"

            regs = []
            current_reg = self.decode_register(rA)
            for i in range(register_count):
                regs.append(current_reg)
                current_reg = get_next_reg(current_reg)

            operands.append(regs)
            operands.append(self.decode_register(rB))
            operands.append(register_count)
            operands.append(m)
            operands.append(mem_offset)

            insn_length = 6
        elif insn.startswith('1011001'):
            opcode = "STW"

            rA = int(insn6[7:12], 2)
            rB = int(insn6[12:17], 2)
            register_count = int(insn6[17:22], 2)+1
            adjust_rB = int(insn6[22:24], 2)
            mem_offset = insn6[24:51]
            mem_offset = int(mem_offset[9:18]+mem_offset[:9]+mem_offset[18:], 2)

            m = ""
            if adjust_rB == 1:
                m = "I"
            elif adjust_rB == 2:
                m = "D"

            regs = []
            current_reg = self.decode_register(rA)
            for i in range(register_count):
                regs.append(current_reg)
                current_reg = get_next_reg(current_reg)

            operands.append(regs)
            operands.append(self.decode_register(rB))
            operands.append(register_count)
            operands.append(m)
            operands.append(mem_offset)

            insn_length = 6
        elif insn.startswith('101000000010000000'):
            opcode = 'WT'
            insn_length = 2
        elif insn.startswith('0011100') and insn[22:26] == '0000':
            opcode = "XR"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0011100') and insn[24:26] == '01':
            opcode = "XRI"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            imm = int(insn3[17:24], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(imm)
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('0011110') and insn[22:26] == '0000':
            opcode = "XRM"

            rA = int(insn3[7:12], 2)
            rB = int(insn3[12:17], 2)
            rC = int(insn3[17:22], 2)
            UF = int(insn3[26], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))
            operands.append(self.decode_register(rC))
            operands.append('.' if UF else '')

            insn_length = 3
        elif insn.startswith('101000001001'):
            opcode = "ZES"

            rA = int(insn3[12:17], 2)
            rB = int(insn3[17:22], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3
        elif insn.startswith('101000001010'):
            opcode = "ZEW"

            rA = int(insn3[12:17], 2)
            rB = int(insn3[17:22], 2)

            operands.append(self.decode_register(rA))
            operands.append(self.decode_register(rB))

            insn_length = 3


        return opcode, operands, (insn_length * 2)

    def perform_get_instruction_info(self, data, addr):
        opcode, operands, insn_length = self.decode_opcode(addr, data)

        result = InstructionInfo()
        result.length = insn_length
        if 'UNIMPLEMENTED' in opcode or \
                opcode == 'HT' or \
                opcode == 'RE' or \
                opcode == 'IR' or \
                opcode == 'DBRK':
            result.add_branch(BranchType.FunctionReturn)
        if opcode == 'CAR' or \
                opcode == 'CAA':
            result.add_branch(BranchType.CallDestination, operands[0])
        if opcode == 'B':
            result.add_branch(BranchType.TrueBranch, operands[2])
            result.add_branch(BranchType.FalseBranch, addr + insn_length)
        if opcode == 'BRA':
            result.add_branch(BranchType.UnconditionalBranch, operands[0])

        return result

    def perform_get_instruction_text(self, data, addr):
        opcode, operands, insn_length = self.decode_opcode(addr, data)

        tokens = tok[opcode](opcode, *operands)

        return tokens, insn_length

    def perform_get_instruction_low_level_il(self, data, addr, il):
        opcode, operands, insn_length = self.decode_opcode(addr, data)

        Lifter.lift(addr, opcode, operands, insn_length, il)

        return insn_length

    def perform_assemble(self, code, addr):
        return None

class ClemencyViewUpdateNotification(BinaryDataNotification):
    def __init__(self, view):
        self.view = view

class ClemencyView(BinaryView):
    name = "Clemency"
    long_name = "Clemency"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data
        self.platform = Architecture['clemency'].standalone_platform

    @classmethod
    def is_valid_for_data(self, data):
        return data.file.filename.endswith('_expanded.bin') or data.file.filename.endswith('_expanded.bndb')

    def init(self):
        try:

            '''
            > mp
            0000000 - 00003ff  00001  R-X
            0000400 - 3ffffff  0ffff  ---
            4000000 - 40003ff  00001  RW-
            4000400 - 400ffff  0003f  ---
            4010000 - 4010fff  00004  R--
            4011000 - 4ffffff  03fbc  ---
            5000000 - 50023ff  00009  RW-
            5002400 - 500ffff  00037  ---
            5010000 - 50123ff  00009  RW-
            5012400 - 50fffff  003b7  ---
            5100000 - 51013ff  00005  R-X
            5101400 - 7fffbff  0bbfa  ---
            7fffc00 - 7ffffff  00001  RW-
            '''

            # program data
            file_size = len(self.raw)
            self.add_auto_segment(0, 0x3FFFFFF, 0, file_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

            # clock
            self.add_auto_segment(0x4000000, 0x3ff, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

            # flag io
            self.add_auto_segment(0x4010000, 0xfff, 0, 0, SegmentFlag.SegmentReadable)

            # data recv
            self.add_auto_segment(0x5000000, 0xffff, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x5002000, "DATARECVSIZE"))

            # data send
            self.add_auto_segment(0x5010000, 0xffff, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x5012000, "DATASENDSIZE"))

            # shared memory
            self.add_auto_segment(0x6000000, 0x7FFFFF, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

            # nvram
            self.add_auto_segment(0x6800000, 0x7FFFFF, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

            # interrupt pointers
            self.add_auto_segment(0x7FFFc00, 0xFFFFF, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

            start = self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0, "_start"))
            self.add_entry_point(0)

            return True
        except:
            log_error(traceback.format_exc())
            return False

    #def perform_is_valid_offset(self, addr):
    #    print "perform_is_valid_offset: ", repr(self.raw), len(self.raw), dir(self.raw)
    #    return addr >= 0 and addr < len(self.raw)

    #def perform_read(self, addr, length):
    #    return 0

    #def perform_is_offset_readable(self, offset):
    #    return addr >= 0 and addr < len(self.raw)

    #def perform_is_offset_writable(self, offset):
    #    return False

    #def perform_get_start(self):
    #    return 0

    #def perform_get_length(self):
    #    return len(self.raw)

    #def perform_is_executable(self):
    #    return True

    #def perform_get_entry_point(self):
    #    return 0

Clemency.register()
ClemencyView.register()
