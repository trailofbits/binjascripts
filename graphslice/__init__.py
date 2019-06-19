from binaryninja.plugin import PluginCommand
import insnslice, varslice


PluginCommand.register_for_medium_level_il_instruction("Slice Variable to Graph",
                                                       "Creates a networkx graph containing all uses of this variable",
                                                       varslice.show_graph)

PluginCommand.register_for_medium_level_il_instruction("Slice Instructions to Graph",
                                                       "Creates a networkx graph containing all uses of this variable",
                                                       insnslice.show_graph)

PluginCommand.register_for_medium_level_il_function("Graph Return variables",
                                                    "Create a graph of all the possible return trees",
                                                    varslice.graph_all_returns)

PluginCommand.register_for_medium_level_il_function("Graph Return Instructions",
                                                    "Create a graph of all the possible return trees",
                                                    insnslice.graph_all_returns)