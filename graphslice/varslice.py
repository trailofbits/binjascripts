import networkx as nx
from functools import reduce
from utils import *
from collections import defaultdict
import pprint as pp


def get_reliability_score(src, dst):
    if src is not None:
        if src.operation == MediumLevelILOperation.MLIL_VAR_PHI:
            return 1.0
    if dst is not None:
        pass
    return 1.0


# Modified from https://gist.github.com/joshwatson/f28b7a2d3356a0ed39823aaea66b50d0
# Thanks Josh!
class VariableSlicer:

    def __init__(self, func):
        self.func = func

        self.instruction_queue = set()
        self.seen_variables = set()
        self.seen_indices = set()
        self.g = nx.DiGraph()
        self.insn_map = defaultdict(set)

    def add_ssa_var(self, _var, i):
        for inst in i:
            if _var in extract_source_variables(inst):
                self.insn_map[node_token(_var)].add(inst)
        if _var not in self.seen_variables:
            if type(_var) is SSAVariable:
                self.g.add_node(node_token(_var), variable=_var)
                self.seen_variables.add(_var)
            else:
                log.log_error("Can't handle variables of type %s" % type(_var))

    def do_slice(self, instruction, direction='bw'):
        self.instruction_queue = {instruction.ssa_form.instr_index}

        while self.instruction_queue:
            visit_index = self.instruction_queue.pop()

            if visit_index is None or visit_index in self.seen_indices:
                continue

            instruction_to_visit = self.func[visit_index]
            for var in extract_all_variables(instruction_to_visit):
                self.add_ssa_var(var, {instruction_to_visit})

            if 'f' in direction.lower():
                self.fw_slice(instruction_to_visit)
            else:
                self.bw_slice(instruction_to_visit)

            self.seen_indices.add(visit_index)

        nx.set_node_attributes(self.g, self.insn_map, 'instructions')

        return prune_orphan_nodes(self.g)

    def bw_slice(self, instruction_to_visit):
        for new_var in extract_source_variables(instruction_to_visit):
            if type(new_var) is SSAVariable:
                definition = self.func.get_ssa_var_definition(new_var)
                if definition is not None:
                    self.instruction_queue.add(definition)
                    self.add_ssa_var(new_var, {self.func[definition]})
                for v in instruction_to_visit.vars_written:
                    self.g.add_edge(node_token(new_var), node_token(v),
                                    weight=get_reliability_score(self.func[definition] if definition is not None else None,
                                                                 instruction_to_visit))

    def fw_slice(self, instruction_to_visit):
        for new_var in extract_dest_variables(instruction_to_visit):
            if type(new_var) is SSAVariable:
                uses = set()
                for use in self.func.get_ssa_var_uses(new_var):
                    self.instruction_queue.add(use)
                    uses.add(self.func[use])
                self.add_ssa_var(new_var, uses)
                for v in extract_source_variables(instruction_to_visit):
                    self.g.add_edge(node_token(v), node_token(new_var),
                                    # TODO - forward slicing is tricky because new_var can have multiple uses
                                    weight=get_reliability_score(instruction_to_visit, None))


def build_graph(instruction, squash_loops=False):
    print "Building graph!"
    func = instruction.function.ssa_form
    g = nx.algorithms.operators.binary.compose(VariableSlicer(func).do_slice(instruction),
                                               VariableSlicer(func).do_slice(instruction, direction='fw'))

    return g if not squash_loops else squash_and_relabel(g)


def var_graph_to_insn_graph(g):
    mapping = nx.get_node_attributes(g, 'instructions')
    pp.pprint(mapping)
    out = nx.DiGraph()
    out.add_nodes_from(i for l in mapping.values() for i in l)
    escaped = {insn: node_token(insn) for l in mapping.values() for insn in l}
    for start, end in g.edges():
        if mapping[start] != mapping[end]:
            for s in mapping[start]:
                for e in mapping[end]:
                    out.add_edge(s, e, weight=1.0)

    return nx.relabel_nodes(out, escaped)


def show_graph(_, instruction):
    draw_graph(build_graph(instruction))


def build_graph_of_all_returns(func):
    graphs = [build_graph(ret) for ret in get_returns(func)]
    if graphs:
        return reduce(lambda a, x: nx.algorithms.operators.binary.compose(a, x), graphs)


def graph_all_returns(_, func):
    draw_graph(build_graph_of_all_returns(func.ssa_form))


# TODO - handle value analysis for sources
