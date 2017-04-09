#!/usr/bin/env python

'''
Example output:
```bash    
    $ python binja_memcpy.py /bin/bash
    Analyzing /bin/bash
    100010818	dst:<undetermined>
    		src:<undetermined>
    		n:<undetermined>
    
    1000109ea	dst:<undetermined>
    		src:<undetermined>
    		n:<undetermined>
    
    100010a49	dst:<undetermined>
    		src:<undetermined>
    		n:<undetermined>
    
    100015857	dst:<undetermined>
    		src:<entry rdi>
    		n:<range: -0x80000000 to 0x7fffffff>
    
    100015cf0	dst:<undetermined>
    		src:<entry rdi>
    		n:<undetermined with offset -0x1>
    
    100015d01	dst:<undetermined with offset -0x1>
    		src:<entry rsi>
    		n:<entry rdx>
    
    10002189f	dst:<stack frame offset -0xc8>
    		src:<const 0x10008fe00>
    		n:<const 0x98>
    
    10002192e	dst:<const 0x10008fe00>
    		src:<stack frame offset -0xc8>
    		n:<const 0x98>
    
    10002a7f8	dst:<undetermined>
    		src:<undetermined>
    		n:<range: -0x80000000 to 0x7fffffff>
    
    10002ada5	dst:<undetermined>
    		src:<undetermined>
    		n:<undetermined>
```
'''

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

    dst = function.get_parameter_at(addr, None, 0)
    src = function.get_parameter_at(addr, None, 1)
    n = function.get_parameter_at(addr, None, 2)
    print "{:x}\tdst:{}\n\t\tsrc:{}\n\t\tn:{}\n".format(addr, dst, src, n)

