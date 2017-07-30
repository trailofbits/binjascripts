#!/usr/bin/env python

import os
import sys
import struct

from bitstream import BitStream

'''
A simple packer @quend

Usage.
1) Unpack binary
2) Edit bytes (each 2 bytes correlates with a 3 nibble byte in the debugger)
3) Pack edited binary
4) Win  
'''

def unpack():
    contents = open(sys.argv[2], 'rb').read()
    output_file = open(sys.argv[3], 'wb')

    bits = BitStream(contents)

    i = len(bits)
    while i > 0:
        b =  bits.read(9)
        i -= 9

        b = '0000000' + str(b)

        sh = int(b, 2)
        x = struct.pack("H", sh) 
        output_file.write(x)

def pack():
    contents = open(sys.argv[2], 'rb').read()
    packed_file = open(sys.argv[3], 'wb')


    bits = BitStream(contents)
    f = ''

    i = len(bits)
    while i > 0:
        b =  bits.read(16)
        i -= 16

        # dirty flip to deal with endianness
        b = str(b)[8:] + str(b)[:8]
        b = b[7:]
        f += b
    
    packed_bitstream = BitStream()
    for i in f:
	packed_bitstream.write(int(i), bool)

    for i in range(0, len(packed_bitstream)/8):
        b = packed_bitstream.read(8)
        packed_file.write(struct.pack('B', int(str(b), 2)))
         
if len(sys.argv) != 4:
    print '[!] Usage: python transform.py <pack/unpack> input.bin output.bin'

if sys.argv[1] == 'pack':
    pack()
elif sys.argv[1] == 'unpack':
    unpack()
