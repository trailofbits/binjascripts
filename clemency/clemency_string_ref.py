#!/usr/bin/env python

import os
import sys
from binaryninja import *
import struct

def read_string(bv, addr):
    out = bv.read(addr, 256)
    shorts = struct.unpack("128H", out)
    for i, s in enumerate(shorts):
        if s == 0:
            shorts = shorts[:i]
            break

    out = ''.join([chr(x) for x in shorts])

    print repr(out)
    return out

def plugin_exec(bv, addr):
    blocks = bv.get_basic_blocks_at(addr)
    func = blocks[0].function

    choices = ['r0' ,
            'r1',
            'r2',
            'r3',
            'r4',
            'r5',
            'r6',
            'r7',
            'r8',
            'r9',
            'r10',
            'r11',
            'r12',
            'r13',
            'r14',
            'r15',
            'r16',
            'r17',
            'r18',
            'r19',
            'r20',
            'r21',
            'r22',
            'r23',
            'r24',
            'r25',
            'r26',
            'r27',
            'r28',
            'st',
            'ra',
            'pc',
            ]

    reg = get_choice_input('Which register?', 'String Ref', choices)
    v = func.get_reg_value_after(addr, choices[reg])

    if v.type != RegisterValueType.ConstantValue:
        log_info("register is not a constant type {}".format(v))
        return

    cmt = read_string(bv, v.value * 2)
    log_info("str: {}".format(cmt))

    func.set_comment_at(addr, cmt)

PluginCommand.register_for_address("Clemency String Ref", "", plugin_exec)
