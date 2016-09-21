#!/usr/bin/env python

import os
import sys
import binaryninja

inputfile = sys.argv[1]

print "Analyzing {0}".format(inputfile)
bv = binaryninja.BinaryViewType["Mach-O"].open(inputfile)
bv.update_analysis_and_wait()

memcpy_symbol = bv.get_symbol_by_raw_name("_memcpy")
for ref in bv.get_code_refs(memcpy_symbol.address):
    function = ref.function
    addr = ref.address

    dst = function.get_parameter_at(bv.arch, addr, None, 0)
    src = function.get_parameter_at(bv.arch, addr, None, 1)
    n = function.get_parameter_at(bv.arch, addr, None, 2)
    print "{:x}\tdst:{}\n\t\tsrc:{}\n\t\tn:{}\n".format(addr, dst, src, n)

