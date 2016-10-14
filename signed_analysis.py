from binaryninja import *

class abstract_domain(object):
	'''
	A variable is either known to be + , - or 0
	if not, var is either ?: "don't know" 
	or NA: an expression which is not a number (i.e. pointers)
	'''

	domain = ["+", "-", "0", "?", "NA"]
	def __init__(self, abstract_value = "?"):
		self.val = abstract_value
	
	def set_value(self, abstract_value):
		self.val = abstract_value

	def return_val(self):
		return self.val

class abstract_variable(object):
	'''
	a variable has a map of abstract values 
	a value is added to a variable's map with the instruction the information came from
		binja_inst, abstract_domain 
	
	a variable also has a name and a reference to the binja variable object
	'''

	def __init__(self, name, binja_var = None, binja_inst = None, abstract_domain = abstract_domain()):
		self.name = name
		self.binja_var = binja_var
		self.m = []
		(self.m).append([binja_inst, abstract_domain])
	
	def add_value(self, binja_inst, abstract_domain):
		(self.m).append([binja_inst, abstract_domain])
		return self.m
	
	def get_current_inst(self):
		return ((self.m)[-1])[0]

	def alter_current_abstract_domain(self, val):
		((self.m)[-1])[1].set_value(val)

	def get_current_abstract_domain(self):
		return ((self.m)[-1])[1]

	def get_binja_var(self):
		return self.binja_var
	
	def get_name(self):
		return self.name

class abstract_path(object):
	'''
	TODO: multiple paths based on BFS traversal
	a path is one branch of a programs possible execution
	'''

	def __init__(self, name, set_abstract_variables = []):
		self.name = name
		self.s = set_abstract_variables
	
	def add_variable(self, var):
		(self.s).append(var)
		return self.s

	def get_name(self):
		return self.name
	
	def get_current_set_vars(self):
		return self.s
	
	def contains(self, name):
		for v in self.s:
			if v.get_name() == name:
				print v.get_name(), name
				return True
		return False

	def get(self, name):
		for v in self.s:
			if v.get_name() == name:
				return v 

class abstract_lattice(object):
	'''
	A program lattice is the set of possible execution paths
	each with distinct variable signs 
	A new path is added at each branching IF instruction
	'''

	def __init__(self, name, set_abstract_paths = []):
		self.name = name
		self.sp = set_abstract_paths

	def add_path(self, path):
		(self.sp).append(path)

	def get_path(self, path_name):
		for p in self.sp:
			if path_name == p.get_name():
				return p

class registers(object):
	
	def __init__(self):
		self.eax = abstract_variable('eax') 
		self.ebx = abstract_variable('ebx') 
		self.ecx = abstract_variable('ecx') 
		self.edx = abstract_variable('edx') 

	def check(self, reg):
		#if reg == "eax" or reg == "ebx" or reg == "ecx" or reg == "rax" or reg == "rbx" or reg == "rcx" or reg == "edx" or reg == "rdx":
		return True
		#return False

	def update_registers(self, reg, val):
		# TODO: implement logic for r/e registers
		if reg == "eax" or reg == "rax":
			(self.eax).alter_current_abstract_domain(val)

		if reg == "ebx" or reg == "rbx":
			(self.ebx).alter_current_abstract_domain(val)

		if reg == "ecx" or reg == "rcx":
			(self.ecx).alter_current_abstract_domain(val)

		if reg == "edx" or reg == "rdx":
			(self.edx).alter_current_abstract_domain(val)

	def get_current_abstract_domain(self, reg):
		if reg == "eax" or reg == "rax":
			return (self.eax).get_current_abstract_domain()

		if reg == "ebx" or reg == "rbx":
			return (self.ebx).get_current_abstract_domain()

		if reg == "ecx" or reg == "rcx":
			return (self.ecx).get_current_abstract_domain()
		
		if reg == "edx" or reg == "rdx":
			return (self.edx).get_current_abstract_domain()


def trace_variables(view, inst, func):
	for o in inst.operands:
		if type(o) == type(inst):
			# o is an instruction
			#print func.get_stack_vars_referenced_by(view.arch, o.address)
			#print o
			#print type(o)
			trace_variables(view, o, func)
			#for t in o.tokens:
			#	print t
			#	print type(t)
		else:
			print o
			#print type(o)
		#elif type(o) == type(str):
		#	print 'found variable string to trace'
		#	print o
	
def check_signedness_operation(view, inst, func):
	found = False
	if "LLIL_CMP_S" in inst.operation_name:
		#print '\n[+] Signed cmp'
		#print "\t\t{0}\n".format(inst)	
		found = True
	if "LLIL_CMP_U" in inst.operation_name:
		#print '\n[-] Unsigned cmp'
		#print "\t\t{0}\n".format(inst)	
		found = True
	if "LLIL_SX" == inst.operation_name:
		#print '\n[!] Found size_t cast of signed integer.'
		#print "\t\t{0}\n".format(inst)	
		found = True

	if found:
		print func.get_stack_vars_referenced_by(view.arch, inst.address)
		# check if in map, if so add signess type, if not, add
		# add info about +-0\? or not signed potential
		# print out in comment
		trace_variables(view, inst, func)

def check_sign_at_instantiation(abstract_var, inst, regs):
	if "LLIL_STORE" == inst.operation_name:
		# int of 4 bytes for example
		# print inst.size
		# assume 2nd operand is source, 1st is dest variable 
		if "LLIL_CONST" == (inst.operands[1]).operation_name:
			concrete_value = int(inst.operands[1].operands[0])
			if concrete_value == 0:
				abstract_var.alter_current_abstract_domain("0")
			elif concrete_value > 0:
				abstract_var.alter_current_abstract_domain("+")
			elif concrete_value < 0:
				abstract_var.alter_current_abstract_domain("-")
			return concrete_value

		# if set with register, check if reg has sign, if not set to ?
		# TODO: prompt if not set
		elif "LLIL_REG" == (inst.operands[1]).operation_name:
			reg = str(inst.operands[1])
			if regs.check(reg) == True:
				x = regs.get_current_abstract_domain(reg)
				if x == None:
					return ""
				abstract_var.alter_current_abstract_domain(x.return_val())
				return "" #x.return_val() 
			else:
				regs.update_registers(reg, "?")
				abstract_var.alter_current_abstract_domain("?")
				return "" #"?" 

	#print 'NOT IMPLEMENTED !!!!'
	#print inst.operation_name
	abstract_var.alter_current_abstract_domain("?")
	return ""


def update_registers(view, func, inst, regs, path):
	
	# if reg isnt in our abstract regs, we dont care about it for now
	if regs.check(str(inst.operands[0])) == False:
		return ""

	if "LLIL_SET_REG" == inst.operation_name:
		new_inst_str = ""
		new_inst = None
		if type(inst.operands[1]) == type(inst):
			new_inst = inst.operands[1]
			new_inst_str = inst.operands[1].operation_name
		
		#print new_inst_str
		#print

		# signed cast! perform check for checks and alert
		if "LLIL_SX" == new_inst_str:
			#print "\n[+] Found signed int cast to unsigned int!\n"
			dest_reg = str(inst.operands[0])
			src_reg = str(new_inst.operands[0])
			
			# check for int possible +/- here
			# maybe also check is used by func call or something else before getting reset somehow - like a special AD flag
			ad = regs.get_current_abstract_domain(src_reg)
			if ad == None:
				return ""
			ad2 = regs.get_current_abstract_domain(dest_reg)
			if ad2 == None:
				return ""
			
			# unsigned case means +, could be very large though!
			if ad.return_val() == "unsigned":
				regs.update_registers(dest_reg, "?")
			else:
				regs.update_registers(dest_reg, ad.return_val())
			return dest_reg + ": " + regs.get_current_abstract_domain(dest_reg).return_val()

		# reg set by a constant
		if "LLIL_CONST" == new_inst_str:
			const = str(new_inst.operands[0]).replace(".", "")
			if const.isdigit() == True:
				reg = str(inst.operands[0])
				cd = ""
				if float(const) > 0:
					cd = "+"
				elif float(const) < 0:
					cd = "-"
				elif float(const) == 0:
					cd = "0"
				else:
					cd = "?"
				regs.update_registers(reg, cd)
				return reg + ": " + cd 
		
		# reg set by a reg
		if "LLIL_REG" == new_inst_str:
			x = regs.get_current_abstract_domain(str(new_inst.operands[0]))
			if x == None:
				return ""
			reg = str(inst.operands[0])
			regs.update_registers(reg, x.return_val())
			return reg + ": " + x.return_val() 
		
		# reg set by a subtraction
		if "LLIL_ADD" == new_inst_str:
			reg = str(inst.operands[0])
			x = regs.get_current_abstract_domain(reg)
			y = None

			# assume reg is first operand of 2nd inst, var is 2nd (aka 1st op is the dest of the whole expr)
			for v in func.get_stack_vars_referenced_by(view.arch, new_inst.address):
				if path.contains(v.name) == True:
					variable = path.get(v.name)
					# this is subtraction!
					y = variable.get_current_abstract_domain()
			
			if y == None :
				if regs.check(str(new_inst.operands[1])) == True:
					y = regs.get_current_abstract_domain(str(inst.operands[1]))
				else:	
					const = str(new_inst.operands[1]).replace(".", "")
					if const.isdigit() == True:
						if float(const) > 0:
							y = abstract_domain("+") 
						elif float(const) < 0:
							y = abstract_domain("-") 
						else:
							y = abstract_domain("0") 
					
			if y == None:
				return "ERROR in Y " 
			
			if x == None:
				return "ERROR in X" 
			if x.return_val() == "+" and y.return_val() == "+":
				regs.update_registers(reg, "+")
			elif x.return_val() == "-" and y.return_val() == "-":
				regs.update_registers(reg, "-")
			elif x.return_val() != "0" or y.return_val() != "0":
				regs.update_registers(reg, "?")
			return "ADD sets " + reg + ": " + regs.get_current_abstract_domain(reg).return_val()  
			
		# reg set by a subtraction
		if "LLIL_SUB" == new_inst_str:
			reg = str(inst.operands[0])
			x = regs.get_current_abstract_domain(reg)
			y = None
			variable = None
			for v in func.get_stack_vars_referenced_by(view.arch, new_inst.address):
				if path.contains(v.name) == True:
					variable = path.get(v.name)
					# this is subtraction!
					y = variable.get_current_abstract_domain()
			if y == None:
				if regs.check(str(new_inst.operands[1])) == True:
					y = regs.get_current_abstract_domain(str(inst.operands[1]))
				else:
					const = str(new_inst.operands[1]).replace(".", "")
					if const.isdigit() == True:
						if float(const) > 0:
							y = abstract_domain("+") 
						elif float(const) < 0:
							y = abstract_domain("-") 
						else:
							y = abstract_domain("0") 
						
			if y == None:
				return "ERROR in Y"
			
			# this is subtraction!
			if x == None:
				return "ERROR in X"

			if x.return_val() == "+" and y.return_val() == "-":
				regs.update_registers(reg, "+")
			elif x.return_val() == "-" and y.return_val() == "+":
				regs.update_registers(reg, "-")
			elif x.return_val() != "0" or y.return_val() != "0":
				regs.update_registers(reg, "?")

			return "SUB sets " + reg + ": " + regs.get_current_abstract_domain(reg).return_val() 
			
		# basic set using 1 src
		else:		
			reg = str(inst.operands[0])
			for v in func.get_stack_vars_referenced_by(view.arch, inst.address):
				if path.contains(v.name) == True:
					variable = path.get(v.name)
					regs.update_registers(reg, variable.get_current_abstract_domain().return_val())
					return reg + ": " + variable.get_current_abstract_domain().return_val() 

	return ""

def update_variables(view, func, inst, regs, path):
	# assuming the dest operand is a variable
	# TODO: deal with branch instructions befor this point
	if len(inst.operands) < 2:
		return ""
	op = inst.operation_name
	
	if "LLIL_STORE" == op:
		src = regs.get_current_abstract_domain(str(inst.operands[1]))
		if src != None:
			for v in func.get_stack_vars_referenced_by(view.arch, inst.address):
				variable = path.get(v.name)
				variable.alter_current_abstract_domain(src.return_val())
				return v.name + ": " + src.return_val() 
		# maybe its constant
		const = str(inst.operands[1]).replace(".", "")
		if const.isdigit() == True:
			for v in func.get_stack_vars_referenced_by(view.arch, inst.address):
				variable = path.get(v.name)
				if float(const) > 0:
					cd = "+"
				elif float(const) < 0:
					cd = "-"
				elif float(const) == 0:
					cd = "0"
				else:
					cd = "?"
				variable.alter_current_abstract_domain(cd)
				return v.name + ": " + cd 
		
		# maybe its a variable, assumes 1st var in get_stack_vars is the dest operand
		src_var = str(inst.operands[1])
		if path.contains(src_var) == False:
			# add var (its probably a unimplemented register)
			extern_var = abstract_variable(src_var, inst.operands[1], inst)
			path.add_variable(extern_var)

		sv = path.get(src_var)
		for v in func.get_stack_vars_referenced_by(view.arch, inst.address):
			if src_var != v.name:
				variable = path.get(v.name)
				variable.alter_current_abstract_domain(sv.get_current_abstract_domain().return_val())
				return v.name + ": " + variable.get_current_abstract_domain().return_val() 

	return ""

# TODO: right now assumes everything starts as signed, maybe could group that into the ? category
def function_sign_analysis(view, func, recurse_level, ap, regs):
	'''
	Perform signed analysis using lattice theory described here:
	https://cs.au.dk/~amoeller/spa/spa.pdf
	'''

	if recurse_level > 4:
		return

	# print repr(func)
	for block in func.low_level_il:
		# print "\t{0}".format(block)
		for insn in block:
			# print insn.operation, insn.operation_name
			# check if (un)signed operation is a operand of main operation
			# do this recursively 
			new_vars = False
			if insn.operation_name == "LLIL_NORET":
				#print "NORET found, continuing.... "
				continue
			
			if insn.operation_name == "LLIL_UNIMPL":
				#print "UNIMPL found, continuing.... "
				continue
			
			if insn.operation_name == "LLIL_CALL":
				# regs may change! check if we know @ the call
				# also check for set flag after to determine bounds of eax
				regs.update_registers("eax", "?")
				#print "CALL found, eax is changed. ", insn
				call = str(insn.operands[0].operands[0]).replace("x", "")	
				if call.isdigit() == True:
					called = int(insn.operands[0].operands[0])
					#print 'Address of called function: ', hex(called)
					called_func = view.get_recent_function_at(called)
					if "memcpy" == called_func.name:
						# know rdx is implicitly cast to unsigned!
						ad = regs.get_current_abstract_domain("rdx")
						if ad.return_val() != "unsigned":
							msg = "[!] Found SX cast of a signed integer rdx. Vulnerable to type confusion.\n" 
							func.set_comment(insn.address, msg)
					elif len(called_func.low_level_il.basic_blocks) <= 1:
						pass #print 'External function call'
					else:
						# we follow into the func
						msg = "Following into function call: " + str(called_func.name)
						
						if recurse_level > 4:
							return
						recurse_level += 1
						msg += "\n[!] Recursion level: " + str(recurse_level) + "\n"
						func.set_comment(insn.address, msg)
						function_sign_analysis(view, called_func, recurse_level, ap, regs)

			if insn.operation_name == "LLIL_SET_FLAG":
				# may tell us something about the register
				#print "FLAG found, reg is checked. ", insn
				if type(insn.operands[1]) == type(insn):
					ni = insn.operands[1]

					# check if cmp for < 0 before this at all in the given path
					if "LLIL_CMP_SGT" == ni.operation_name:
						#print "Signed compare, checking -/+ int boundries!"
						#print str(ni.operands[0]) + " is a signed int"
						# update var and regs
						func.set_comment(insn.address, str(ni.operands[0]) + ": ? \n[!] Register " + str(ni.operands[0]) + " is a signed int.")

			# branches do not implement new vars, nor alter var/ reg values
			#if insn.operation_name == "LLIL_IF":
				#path_count += 1
				#new_ap = abstract_path("branch+" + str(path_count))
				#program.add_path(new_ap)
				
			# loop for new variables
			for v in func.get_stack_vars_referenced_by(view.arch, insn.address):
				if ap.contains(v.name) == False:
						av = abstract_variable(v.name, v, insn)
						concrete_string = "" 
						concrete = check_sign_at_instantiation(av, insn, regs)
						if concrete != "":
							# print concrete value in annotations
							# we do not keep track of concrete values 
							concrete_string += str(concrete)	
						ap.add_variable(av)	
						new_vars = True
						func.set_comment(insn.address, av.name + ": " + (av.get_current_abstract_domain()).return_val() + concrete_string)

			if new_vars == False:
				# update current registers and variables
				update = update_registers(view, func, insn, regs, ap)
				if update != "":
					func.set_comment(insn.address, "[+] Reg Update\n " + update)
				
				else:
					update = update_variables(view, func, insn, regs, ap)	
					if update != "":
						func.set_comment(insn.address, "[+] Variables updated\n " + update)
			#continue
			#for o in insn.operands:
			#	if type(o) == type(insn):
			#		print 'operands'
			#		print o
			#		print func.get_stack_vars_referenced_by(view.arch, o.address)
					#check_signedness_operation(view, o, func)
			#check_signedness_operation(view, insn, func)


def function_sign_analysis_start(view, func):
	regs = registers() 
	program = abstract_lattice("test2")
	ap = abstract_path("start")
	program.add_path(ap)
	path_count = 0
	function_sign_analysis(view, func, 0, ap, regs)

PluginCommand.register_for_function("Full Function Sign Analysis", "Analysis to find possible signs of variables in a given function and places where variable signs are changed.", function_sign_analysis_start)
