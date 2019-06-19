from binaryninja.mediumlevelil import MediumLevelILOperation, MediumLevelILInstruction, SSAVariable
import networkx as nx
import matplotlib.pyplot as plt
from binaryninja import log


def extract_retn_sources(insn):
    """ Handles cases when the return address doesn't have a source, or sources from something other than rax. """
    sources = insn.src
    out = []
    for s in sources:
        if s.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            out.append(s.src)
        elif s.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            pass  # TODO - handle constant pointers
    # TODO - handle returns without a source
    return out


def extract_all_variables(instruction):
    out = set()
    if instruction.operation == MediumLevelILOperation.MLIL_RET:
        for src in extract_retn_sources(instruction):
            out.add(src)
    if instruction.vars_read and instruction.operation != MediumLevelILOperation.MLIL_CALL_SSA:
        out.update((i for i in instruction.vars_read))
    if instruction.vars_written:
        out.update((i for i in instruction.vars_written))

    return out


# No way to register a plugin callback for the current variable yet, so this is the best we can do
def extract_source_variables(instruction):
    if instruction.operation == MediumLevelILOperation.MLIL_RET:
        return extract_retn_sources(instruction)
    if instruction.operation == MediumLevelILOperation.MLIL_CALL_SSA:
        return []
    return instruction.vars_read


def extract_dest_variables(instruction):
    return instruction.vars_written


def node_token(node):
    if type(node) is MediumLevelILInstruction:
        return str(node).decode('utf-8')
    elif type(node) is SSAVariable:
        return "{}#{}".format(node.var.name, node.version)
    else:
        log.log_warn("No way to stringify node of type %s" % type(node))
        return str(node)


def squash_and_relabel(g):
    if not nx.is_directed_acyclic_graph(g):
        log.log_info("Squashing loops")
        g = nx.algorithms.components.condensation(g)  # one line to squash the loops
        # seven lines to rename the nodes
        mapping = {}
        for i in range(len(g.nodes)):
            if len(g.nodes[i]['members']) == 1:
                mapping[i] = g.nodes[i]['members'].pop()
            else:
                mapping[i] = 'U'.join(n for n in g.nodes[i]['members'])
        return nx.relabel_nodes(g, mapping)


def prune_orphan_nodes(g):
    """ Sometimes (ie MLIL_IF) we have a source variable that has nothing to do with the variable we want to slice. """
    subg = list(nx.weakly_connected_component_subgraphs(g))
    if len(subg):
        return max(subg, key=len)
    return g


def count(itr):
    return sum(1 for _ in itr)


def get_returns(mlil_func):
    return filter(lambda x: x.operation == MediumLevelILOperation.MLIL_RET,
                  (i for bb in mlil_func.ssa_form for i in bb))


def get_ret_counts(bv):
    for func in bv.functions:
        c = count(get_returns(func.medium_level_il))
        yield c, func


def get_sink_nodes(graph):
    for node, odeg in graph.out_degree(graph.nodes()).items():
        if odeg == 0:
            yield node


def get_source_nodes(graph):
    for node, ideg in graph.in_degree(graph.nodes()).items():
        if ideg == 0:
            yield node


def _find_multi_returns(bv):
    for c, f in get_ret_counts(bv):
        if c > 1:
            yield f


def draw_graph(g):
    pos = nx.spring_layout(g)

    fw = [(u, v) for (u, v, d) in g.edges(data=True) if d['weight'] == 1.0]
    pw = [(u, v) for (u, v, d) in g.edges(data=True) if d['weight'] < 1.0]

    nx.draw_networkx(g, pos, edge_color='#bfd7ff')
    # nx.draw_networkx_nodes(g, pos)
    nx.draw_networkx_edges(g, pos, edgelist=fw)
    # nx.draw_networkx_edges(g, pos, edgelist=pw, alpha=0.4, edge_color='b')
    # nx.draw_networkx_labels(g, pos, font_size=10, font_family='sans-serif')

    plt.axis('off')
    plt.show()


def draw_unweighted(g):
    nx.draw_networkx(g)
    plt.axis('off')
    plt.show()
