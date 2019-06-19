import networkx as nx
from binaryninja import MediumLevelILOperation as op
from functools import reduce
from utils import *


def get_reliability_score(src, dst):
    # TODO - support cases other than Phi functions that provide the full value
    if dst.operation in {op.MLIL_CALL_SSA, op.MLIL_CALL_PARAM_SSA}:
        return 0.0
    if dst.operation in {op.MLIL_VAR_PHI, op.MLIL_VAR_SSA, op.MLIL_VAR_ALIASED}:
        return 1.0
    return 1.0


# Modified from https://gist.github.com/joshwatson/f28b7a2d3356a0ed39823aaea66b50d0
# Thanks Josh!
def var_slice_wrapper(instruction, func, slice_func):
    # switch to SSA form (this does nothing if it's already SSA).
    instruction_queue = {instruction.ssa_form.instr_index}
    seen_instructions = set()
    seen_indices = set()
    g = nx.DiGraph()

    def add_ssa_inst(_insn):
        if _insn not in seen_instructions:
            if type(_insn) is MediumLevelILInstruction:
                g.add_node(node_token(_insn), instruction=_insn, variables=extract_all_variables(_insn))
                seen_instructions.add(_insn)
            else:
                log.log_error("Can't handle objects of type %s" % type(_insn))
        else:
            log.log_warning("Already handled instruction %s" % _insn)

    while instruction_queue:
        visit_index = instruction_queue.pop()

        if visit_index is None or visit_index in seen_indices:
            continue

        instruction_to_visit = func[visit_index]
        add_ssa_inst(instruction_to_visit)

        slice_func(instruction_to_visit, func, instruction_queue, add_ssa_inst, g)

        seen_indices.add(visit_index)

    return prune_orphan_nodes(g)


def bw_slice(instruction, f):

    def slice_func(instruction_to_visit, func, instruction_queue, add_ssa_inst, g):
        for new_var in extract_source_variables(instruction_to_visit):
            if type(new_var) is SSAVariable:
                definition = func.get_ssa_var_definition(new_var)
                if definition is not None:
                    instruction_queue.add(definition)
                    src = func[definition]
                    add_ssa_inst(src)
                    g.add_edge(node_token(src), node_token(instruction_to_visit),
                               weight=get_reliability_score(src, instruction_to_visit))

    return var_slice_wrapper(instruction, f, slice_func)


def fw_slice(instruction, f):

    def slice_func(instruction_to_visit, func, instruction_queue, add_ssa_inst, g):
        for new_var in extract_dest_variables(instruction_to_visit):
            if type(new_var) is SSAVariable:
                for use in func.get_ssa_var_uses(new_var):
                    if use is not None:
                        instruction_queue.add(use)
                        dst = func[use]
                        add_ssa_inst(dst)
                        g.add_edge(node_token(instruction_to_visit), node_token(dst),
                                   weight=get_reliability_score(instruction_to_visit, dst))

    return var_slice_wrapper(instruction, f, slice_func)


def build_graph(instruction, squash_loops=False):
    func = instruction.function.ssa_form
    b = bw_slice(instruction, func)
    f = fw_slice(instruction, func)
    g = nx.algorithms.operators.binary.compose(b, f)

    return g if not squash_loops else squash_and_relabel(g)


def _to_unicode(insn):
    return str(insn).decode('utf-8')


def show_graph(_, instruction):
    draw_graph(build_graph(instruction))


def build_graph_of_all_returns(func):
    graphs = [build_graph(ret) for ret in get_returns(func)]
    if graphs:
        return reduce(lambda a, x: nx.algorithms.operators.binary.compose(a, x), graphs)


def graph_all_returns(_, func):
    draw_graph(build_graph_of_all_returns(func.ssa_form))


# TODO - convert variable graph to instruction graph (fully)
# TODO - handle value analysis for sources
