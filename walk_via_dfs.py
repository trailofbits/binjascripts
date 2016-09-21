from binaryninja import *

def get_LowLevelILBasicBlock_from_bb(view, func, inst):
	for block in func.low_level_il:
		for i in block:
			if i.address == inst.address:
				return block
	return None

def keep_walking(block):
	# TODO: track has_undetermined_outgoing_edges
	for inst in block:
		print type(inst)
		print inst
		# if means 2 branches, may return
		if "LLIL_IF" == inst.operation_name:
			print '\n[+] Found a branching inst, edge count == ', len(block.outgoing_edges)
			for edge in block.outgoing_edges:
				
				next_il_inst = ((block.function).low_level_il)[edge.target]
				next_il_block = get_LowLevelILBasicBlock_from_bb(block.view, block.function, next_il_inst)
				keep_walking(next_il_block)

		# calls mean 1 branch, may return
		if "LLIL_CALL" == inst.operation_name:
			print '\n[+] Found a calling inst, this means we may follow the call'

	# basic case of 1 branch
	print '\n[+] Basic branch ', inst.operation_name
	print '[!] This should be 1: ', len(block.outgoing_edges)


def start_walking(view, func):
	start_block = func.low_level_il.basic_blocks[0]
	keep_walking(start_block)



PluginCommand.register_for_function("Walk CFG via DFS", "Template to walk a function's cfg using the depth-first search algorithm. Supports following calls up to a depth of n.", start_walking)

