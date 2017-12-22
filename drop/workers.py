# Copyright (C) 2017 Thomas Rinsma / Riscure
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from functools import partial
import threading
import operator
import string
import operator
import sys
import signal

# Qt related
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.Qt import Qt
from PyQt5.QtCore import QThread, QObject, pyqtSignal

# IDA related
import idaapi, idautils, idc
from idaapi import PluginForm
import sark

# Angr related
import angr
import claripy
import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt

# Other non-builtin packages
import networkx

# Package-local stuff
from helpers import *


claripy_op_mapping = {
    '<': claripy.SLT,
    '>': claripy.SGT,
    '<=': claripy.SLE,
    '>=': claripy.SGE,
    '==': operator.eq,
    '!=': operator.ne
}

# Some magic constants
UNUSED_MEMORY_ADDR = 0xFFFF0000 # TODO: How can we be sure this is unused?

# Configurable parameters. TODO: not really constant so put them in a settings object or something
# Max amount of iterations to do (i.e. basic-blocks to step) in the explore() calls.
CONCRETE_MAX_ITERATIONS = 50
SYMBOLIC_MAX_ITERATIONS = 50


def build_cfg(plugin, ida_func, log_signal):
    """
    Build a CFGAccurate for `ida_func` and store it in `plugin`.
    """
    if plugin.angr_proj.kb.functions.function(ida_func.startEA) is None:
        try:
            log_signal.emit("Making CFGAccurate for {:x}..".format(ida_func.startEA))
            plugin.cfg = plugin.angr_proj.analyses.CFGAccurate(
                context_sensitivity_level=0, # Should be the most similar to IDA: no context
                starts=[ida_func.startEA])
            log_signal.emit("Done making CFG.")
        except:
            #import traceback
            log_signal.emit("Failed to make CFGAccurate, making CFGFast")
            plugin.cfg = plugin.angr_proj.analyses.CFGFast(
                start=ida_func.startEA,
                end=ida_func.endEA
            )

    else:
        log_signal.emit("CFG was already built.")



class IDAFunctionCodeBlocks(object):
    """
    Represents an IDA function with address range and a dict of
    containing IDA code-blocks. Used instead of an IDA or Sark object
    to prevent querying IDA's database when accessing these properties.
    """

    # Function start and end
    startEA = None
    endEA = None

    # Dict of the containing codeblocks:
    #   startEA -> (endEA, succs, preds)
    # where `succs` and `preds` are lists of startEAs of successor/predecessor codeblocks
    codeblocks = None

    # Important: Only init this class in the GUI thread
    def __init__(self, sarkFunc):
        self.startEA = sarkFunc.startEA
        self.endEA = sarkFunc.endEA

        nxg = sark.get_nx_graph(sarkFunc.startEA)
        f_startEAs = nxg.nodes()
        self.codeblocks = {
            cb.startEA: (cb.endEA, map(lambda s: s.startEA, cb.succs()), map(lambda s: s.startEA, cb.preds()))
            for cb in sark.codeblocks(start=self.startEA, end=self.endEA)
            if cb.startEA in f_startEAs
        }

    # Convert any addr within this function to the start address
    # of its containing codeblock
    def addr_to_cb_start_ea(self, addr):
        if addr < self.startEA or addr >= self.endEA:
            return None

        for cb_start_ea in self.codeblocks:
            (cb_end_ea, _, _) = self.codeblocks[cb_start_ea]
            if cb_start_ea <= addr and cb_end_ea > addr:
                return cb_start_ea

        return None

    def succs(self, cb_start_ea):
        return self.codeblocks[cb_start_ea][1]

    def preds(self, cb_start_ea):
        return self.codeblocks[cb_start_ea][2]



# TODO: pass function
class UnreachabilityPropagator(QObject):
    """
    Propagate unreachability information as given by the colors
    of IDA code-blocks.
    
    This is a worker class, meant to be ran inside its own QThread.

    Returns a list of addresses of unreachable IDA code-blocks by
    passing it to the `result_signal`.
    """

    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(list)

    def __init__(self, plugin):
        QObject.__init__(self)
        self.plugin = plugin

    def run(self):
        # All the colors that signify unreachable blocks
        unreachable_cols = [
            col_t2ida(self.plugin.col_unreachable),
            col_t2ida(self.plugin.col_invariant),
            col_t2ida(self.plugin.col_contextual)
        ]

        # helper lambdas
        cb_in_list = lambda cb, l: any(cb.startEA == x.startEA for x in l)
        not_colored_unreach = lambda cb: not cb.color or cb.color not in unreachable_cols
        
        # Get the current function in IDA
        f = sark.Function()

        # Find all yellow, cyan and purple blocks (i.e. already determined unreachable)
        unreachable_blocks = get_all_blocks_of_color(f, unreachable_cols)

        # Start with all white successors of the initial blocks
        possibly_unreachable = []
        for cb in unreachable_blocks:
            for succ in filter(not_colored_unreach, filter(lambda succ: succ.startEA > cb.startEA, cb.succs())):
                possibly_unreachable.append(succ)


        while len(possibly_unreachable) > 0:
            # Pop one from the queue of possibly unreachable blocks
            cb = possibly_unreachable.pop()

            if not not_colored_unreach(cb):
                continue

            # If all our predecessors are unreachable, we're unreachable
            preds_no_backedges = filter(lambda pred: pred.startEA < cb.startEA, cb.preds())
            if all(cb_in_list(pred, unreachable_blocks) for pred in preds_no_backedges):
                self.log_signal.emit("all preds unreachable, changing color of {:x}\n".format(cb.startEA))
                #cb.color = 0xFF00FF
                unreachable_blocks.append(cb)
                # Continue looking at our successors
                for succ in filter(not_colored_unreach,  filter(lambda succ: succ.startEA > cb.startEA, cb.succs())):
                    possibly_unreachable.append(succ)

        # Return results to GUI thread
        unreachable_addrs = map(lambda b: b.startEA, unreachable_blocks)
        self.log_signal.emit("Unreachable blocks: {}".format(unreachable_addrs))
        self.result_signal.emit(unreachable_addrs)


class ConcreteRunner(QObject):
    """
    Run the given function 'concretely' by exploring a pathgroup with
    all of angr's symbolic functionality turned off.

    This is a worker class, meant to be ran inside its own QThread.

    Returns a list of IDA code-blocks visited, by sending it to its
    `result_signal` signal.
    """

    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(list)

    def __init__(self, plugin, ida_func, arg_vals=None):
        QObject.__init__(self)
        self.plugin = plugin
        self.ida_func = ida_func
        self.arg_vals = arg_vals if arg_vals is not None else []

    def run_function_concrete(self):
        """
        Runs function concretely, by turning off all symbolic options in simuvex
        and running an angr Callable.
        """

        # CONCRETIZE
        # SINGLE_EXIT
        # NATIVE_EXECUTION(?)
        # FAST_MEMORY
        # FAST_REGISTERS

        # -SYMBOLIC_INITIAL_VALUES
        # -SYMBOLIC

        # Create an angr callable and perform the call
        st = self.plugin.angr_proj.factory.blank_state(
            addr=self.ida_func.startEA,
            add_options={
                simuvex.o.CONCRETIZE,
                simuvex.o.SINGLE_EXIT,
                simuvex.o.NATIVE_EXECUTION, #?
                #simuvex.o.FAST_MEMORY,
                simuvex.o.FAST_REGISTERS
            },
            remove_options={
                simuvex.o.SYMBOLIC_INITIAL_VALUES,
                simuvex.o.SYMBOLIC
            }
        )

        # Create claripy concrete values
        params = []
        free_mem = UNUSED_MEMORY_ADDR # Some location in memory that should be available. TODO: make sure
        for val in self.arg_vals:
            # In the case of string constants, store them in memory
            if len(val) >= 2 and val[0] == val[-1] == '"':
                st.memory.store(free_mem, claripy.BVV(val[1:-1])) # Store the string (without quotes) in available memory
                params.append(claripy.BVV(free_mem, self.plugin.bitness)) # Pass a pointer to the string we stored
                free_mem += self.plugin.angr_proj.arch.bytes
            else:
                try:
                    params.append(claripy.BVV(int(val), self.plugin.bitness))
                except:
                    # Given param probably didn't convert to an integer properly
                    # TODO: proper error message
                    return []

        try:
            # Create a call state for our concrete execution
            self.log_signal.emit("Running function concretely..")
            star_args = [self.ida_func.startEA] + params
            concrete_call_state = self.plugin.angr_proj.factory.call_state(*star_args, base_state=st)
            concrete_path = self.plugin.angr_proj.factory.path(concrete_call_state)
            concrete_pg = self.plugin.angr_proj.factory.path_group(concrete_path)
            et_loop_limiter = angr.exploration_techniques.looplimiter.LoopLimiter(count=1, discard_stash='spinning')
            concrete_pg.use_technique(et_loop_limiter)

            # TODO: somehow limit the depth of called functions as well as the max iterations
            concrete_pg.explore(
                n=CONCRETE_MAX_ITERATIONS       # Max amount of iterations.
            )
        except:
            self.log_signal.emit("ERROR: Couldn't call function concretely (probably no paths found to exit)")
            raise

        # Grab one path, preferably from a non-deadended and non-unsat stash
        paths = (concrete_pg.active + concrete_pg.deadended + concrete_pg.unsat + concrete_pg.unconstrained + concrete_pg.stashed)
        if len(paths) == 0:
            self.log_signal.emit("Didn't find any path at all.. Sorry.")
            raise
        path = paths[0]

        # Retrieve the (angr) irsb addrs that were hit in the trace
        addrs = list(path.addr_trace)


        # Get the intruction addrs for each angr irsb addr
        instr_addrs = flatten_list([self.plugin.angr_proj.factory.block(addr).instruction_addrs for addr in addrs])


        # Get the list of IDA codeblocks that were hit
        ida_block_addrs = []
        for instr_addr in instr_addrs:
            cb_start_ea = self.ida_func.addr_to_cb_start_ea(instr_addr)
            if cb_start_ea != None and (len(ida_block_addrs) == 0 or ida_block_addrs[-1] != cb_start_ea):
                ida_block_addrs.append(cb_start_ea)


        self.log_signal.emit("Addrs hit:\n{}".format(
            '\n'.join(map(hex, ida_block_addrs)))
        )

        # Return the addr trace
        return ida_block_addrs

    def run(self):
        self.log_signal.emit("Start of ConcreteRunner!")

        # Make sure the CFG is built
        build_cfg(self.plugin, self.ida_func, self.log_signal)

        try:
            # Run the function concretely to get a 'trace'
            addr_trace = self.run_function_concrete()
 
            # And send the results back to the GUI thread
            self.result_signal.emit(addr_trace)
        except:
            self.result_signal.emit([])


        self.log_signal.emit("End of ConcreteRunner!")


class OpaquePredicateFinder(QObject):
    """
    Find opaque predicates in the given function, specified by an
    IDAFunctionCodeBlocks object for `ida_func`, and a list of addresses of
    IDA code-blocks that were hit in a 'concrete' trace, or were manually
    selected: `addr_trace`.
    
    This is a worker class, meant to be ran inside its own QThread.

    Returns all its results by emitting the following to its `result_signal`:
    a list of tuples of:
        (
            the function start address
            a list of opaque predicates, as tuples of: (op_addr, op_type, op_str)
            a list of code-block addresses that were hit in the concrete trace
            a list of invariant OPs, as typles of: (branch_addr, succ_sat, succ_unsat)
            a list of contextual OPs, as typles of: (branch_addr, succ_sat, succ_unsat)
            a boolean specifying whether the analysis has finished
        )
    """

    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal('unsigned long long', list, list, list, bool)

    def __init__(self, plugin, ida_func, addr_trace, all_globals_symbolic):
        QObject.__init__(self)
        self.plugin = plugin
        self.ida_func = ida_func
        self.addr_trace = addr_trace
        self.all_globals_symbolic = all_globals_symbolic

    def _pretty_constraint_str(self, ast):
        if type(ast) is NotImplemented.__class__:
            import traceback
            traceback.print_stack()
            return ""
        # Make a more pretty string:
        # (strip '<Bool ' and '>') and rename variables to letters of the alphabet
        var_renames = zip(ast.variables, string.ascii_lowercase)
        cons_str = str(ast)[6:-1]
        for (s_from, s_to) in var_renames:
            cons_str = cons_str.replace(s_from, s_to)
        return cons_str

    def dominator_set(self, block):
        """
        For a given `block`, returns the set of addresses of
        nodes in the CFG that strictly dominate it.
        """

        self.log_signal.emit("Calculating dominator set of {:x}...".format(block))

        #cfg = self.plugin.cfg.copy()
        #cfg.remove_cycles()


        # Shorthands
        #depth = lambda node: 999 if not node.callstack else len(node.callstack._callstack) # weirdly not exposed
        #in_fun = lambda node: node.function_address == f.startEA
        addr_of = lambda node: node.addr

        # The set of dominators
        dominators = set()

        # Set of handled nodes
        handled = set()

        # Starting BlockNode
        block_node = self.plugin.cfg.functions[self.ida_func.startEA].get_node(block)
        #self.log_signal.emit("block_node = {}".format(block_node))
        
        # Perform a DFS on the reverse edges of the graph,
        # starting at `block`, and finishing when nothing is left
        block_queue = [block_node] # Actually just a FIFO 'stack'
        while len(block_queue) != 0:
            node = block_queue.pop()
            if not node:
                continue

            handled.add(node.addr)

            #self.log_signal.emit("Popped node: {}".format(node))

            # Fix successors and predecessors not being 'symmetric'
            preds = node.predecessors()

            #self.log_signal.emit("predecessors: {}".format(preds))

            # Add all preds that have an equal or higher call-depth to queue
            #new_nodes = filter(lambda n: depth(n) >= orig_depth, preds)

            # Filter out already handled nodes (loops?)
            new_nodes = filter(lambda n: n.addr not in handled and type(n) is angr.knowledge.codenode.BlockNode, preds)

            # Add new nodes to the "queue"
            block_queue.extend(new_nodes)
            #self.log_signal.emit("Added nodes: {}".format(new_nodes))

            # Save the preds who are in this function in the set
            dominators |= set(map(addr_of, new_nodes))

        self.log_signal.emit("Done calculating dominator set.")

        return dominators

    def find_branches(self):
        """
        Find 'branches' (i.e. code-blocks which have two immediate successors)
        along the given trace.

        addr_trace: a list of IDA code-block start addrs
        """

        # List of (branch_irsb, reached_succ_irsb, possibly_unsat_succ_irsb)
        branches = []
        branches_seen = []
        # For each addr hit, check if there was another successor
        # that we didn't hit. TODO: does this make sense for complex graphs?
        for idx, addr in enumerate(self.addr_trace):
            succs = self.ida_func.succs(addr)
            if addr not in branches_seen and len(succs) == 2: # TODO: can be more
                reached_irsb = None
                pos_unsat_irsb = None

                # If one succ is never reached later on,
                # it is the unsat branch
                if succs[0] not in self.addr_trace[idx:]:
                    pos_unsat_irsb = succs[0]
                    reached_irsb = succs[1]
                elif succs[1] not in self.addr_trace[idx:]:
                    pos_unsat_irsb = succs[1]
                    reached_irsb = succs[0]
                else:
                    # Otherwise, the one that comes first is the reached one
                    if self.addr_trace[idx:].index(succs[0]) < self.addr_trace[idx:].index(succs[1]):
                        pos_unsat_irsb = succs[1]
                        reached_irsb = succs[0]
                    else:
                        pos_unsat_irsb = succs[0]
                        reached_irsb = succs[1]

                branches.append((addr, reached_irsb, pos_unsat_irsb))
                branches_seen.append(addr)

        # Log result
        #self.log_signal.emit("Branches: {}".format(branches))
        self.log_signal.emit("\nBranches along trace:\n{}\n".format(
            '\n'.join(map(lambda (f,t,u):"{:x} -> {:x}, {:x}".format(f,t,u),
                branches))))

        return branches

    def add_extra_constraints(self, solver, state):
        # Add any manually added extra constraints
        if self.ida_func.startEA in self.plugin.extra_constraints:
            con_tuples = self.plugin.extra_constraints[self.ida_func.startEA]
            for (opr1, op, opr2) in con_tuples:
                # (0, addr) -> a memory address
                # (1, offs) -> an EBP offset      TODO: arch-independent?
                # (2, name) -> a register name
                # (3, val)  -> a constant
                # (4, s)    -> a string
                # (5, (arr, idx))  -> an array with constant index.

                # Skip the atoi-string-array constraints
                if opr1[0] == 5:
                    continue

                # TODO: check endiansness and don't Reverse? (memory.endness)

                # Don't allow a string for the first operand or inequalities with a string as operand
                if opr1[0] == 4 or (opr2[0] == 4 and op != '=='):
                    continue # TODO: show error about these impossible combinations

                if opr2[0] == 4:
                    # Operand 2 is a string, op is '=='

                    # Allow a constant or memory address as first operand
                    # (treat both as start addr of string)
                    # TODO: currently it's a substring check, check for nullbyte to match exactly?
                    if opr1[0] == 0 or opr1[0] == 3:
                        for (i,c) in enumerate(opr2[1]):
                            c_bvv = claripy.BVV(c, 8)
                            solver.add(c_bvv == state.memory.load(opr1[1] + i, 1))
                    else:
                        continue # TODO: error about unsupported operand type

                    self.log_signal.emit("Added extra string constraint")
                    #self.log_signal.emit("Solver constraints: {}".format(solver.constraints))
                else:
                    ast1, ast2 = None, None
                    if opr1[0] == 0:
                        ast1 = state.memory.load(opr1[1]).reversed
                    elif opr1[0] == 1:
                        ast1 = state.memory.load(state.regs.ebp + opr1[1]).reversed
                    elif opr1[0] == 2:
                        # TODO: fix archs where register names contain special characters
                        ast1 = getattr(state.regs, opr1[1].lower())
                    elif opr1[0] == 3:
                        ast1 = claripy.BVV(opr1[1], self.plugin.bitness)

                    if opr2[0] == 0:
                        ast2 = state.memory.load(opr2[1]).reversed
                    elif opr2[0] == 1:
                        ast2 = state.memory.load(state.regs.ebp + opr2[1]).reversed
                    elif opr2[0] == 2:
                        ast2 = getattr(state.regs, opr2[1].lower())
                    elif opr2[0] == 3:
                        ast2 = claripy.BVV(opr2[1], self.plugin.bitness)
                    
                    solver.add(claripy_op_mapping[op](ast1, ast2))
                    self.log_signal.emit("Added extra constraint: {}".format(claripy_op_mapping[op](ast1, ast2)))
                    #self.log_signal.emit("Solver constraints: {}".format(solver.constraints))

    def make_global_vars_symbolic(self, state):
        # Optionally make certain global vars symbolic
        if self.ida_func.startEA in self.plugin.symbolic_vars or self.all_globals_symbolic:
            vars_dict = dict(self.plugin.global_vars)
            for var_addr in vars_dict:
                # Only make it symbolic if it was specified
                if not self.all_globals_symbolic and var_addr not in self.plugin.symbolic_vars[self.ida_func.startEA]:
                    continue

                var_name = vars_dict[var_addr]
                # TODO: this assumes everything is either a byte or a word
                is_word = True
                for checkbyte in xrange(1, self.plugin.bitness / 8):
                    if (var_addr + checkbyte) in vars_dict:
                        is_word = False
                        break
                var_size = self.plugin.bitness if is_word else 8
                self.log_signal.emit("Making {} symbolic..".format(var_name))
                #state.memory.make_symbolic(var_name, var_addr, var_size)
                state.memory.store(var_addr, claripy.BVS(var_name, var_size))


    def add_custom_hooks(self):
        # Add any manually added custom hooks
        if self.ida_func.startEA in self.plugin.function_hooks:
            hooks = self.plugin.function_hooks[self.ida_func.startEA]

            for (fun_addr, hook_text, custom_text) in hooks:
                # Hook `fun_addr` to a SimProcedure described
                # by `hook_text`, possibly with argument `custom_text`
                hook_kwargs = None #dict()

                if hook_text == "nop":
                    hook = simuvex.SimProcedures['stubs']['Nop']

                elif hook_text == "printable_char":
                    hook = simuvex.SimProcedures['stubs']['ReturnChar']

                elif hook_text == "unconstrained":
                    hook = simuvex.SimProcedures['stubs']['ReturnUnconstrained']

                elif hook_text == "redirect":
                    hook = simuvex.SimProcedures['stubs']['Redirect']
                    hook_kwargs = {"redirect_to": int(custom_text, base=0)}

                elif hook_text == "constant":
                    class ReturnConstant(simuvex.SimProcedure):
                        def run(self, constant_val=None):
                            return self.state.se.BVV(constant_val, self.state.arch.bits)
                    hook = ReturnConstant
                    hook_kwargs = {"constant_val": int(custom_text, base=0)} # TODO: error handling on int parse

                self.plugin.angr_proj.hook(fun_addr, hook, kwargs=hook_kwargs)



    def setup_argv_atoi_constraints(self, state, atoi_added_constraints):
        # If we have string-array-atoi (argv-like) constraints, build the pointers
        # and the symbolic string
        atoi_special_addrs = dict() # looks like: {0xDEADBEEF: (operator.eq, 0)}
        need_to_hook_atoi = False
        if self.ida_func.startEA in self.plugin.extra_constraints:
            con_tuples = self.plugin.extra_constraints[self.ida_func.startEA]
            ctr = 0
            for (opr1, op, opr2) in con_tuples:
                if opr1[0] == 5: # the string-array-atoi type
                    need_to_hook_atoi = True
                    (arr_addr, arr_idx) = opr1[1]

                    # Get AST for right operand
                    if opr2[0] == 0:
                        ast2 = state.memory.load(opr2[1]).reversed
                    elif opr2[0] == 2:
                        ast2 = getattr(state.regs, opr2[1].lower())
                    elif opr2[0] == 3:
                        ast2 = claripy.BVV(opr2[1], self.plugin.bitness)
                    else:
                        continue # TODO: invalid right operand, show error


                    free_mem_addr = UNUSED_MEMORY_ADDR # TODO: unused memory location, declare somewhere else

                    # Store (free_mem_addr - arr_idx * wordsize) at (arr_addr)
                    would_be_arr_base_addr = free_mem_addr - arr_idx * (self.plugin.bitness / 8)
                    state.memory.store(arr_addr, claripy.BVV(would_be_arr_base_addr, self.plugin.bitness).reversed)

                    # Create a magic constant for my_atoi to detect.
                    str_addr = 0xDEADBEEF + ctr
                    ctr += 1

                    # Store a pointer to (str_addr) at (free_mem_addr)
                    state.memory.store(free_mem_addr, claripy.BVV(str_addr, self.plugin.bitness).reversed)

                    # Add it to the dict for my_atoi to see
                    atoi_special_addrs[str_addr] = (op, ast2)

                    # Make the memory at (free_mem_addr + wordsize) symbolic: our actual string
                    #st.memory.make_symbolic('user_constr_{}'.format(arr_idx), str_addr, 8 * len(opr1[1]))
                    

                    self.log_signal.emit("arr_addr = {:X}".format(arr_addr))
                    self.log_signal.emit("would_be_arr_base_addr = {:X}".format(would_be_arr_base_addr))
                    self.log_signal.emit("free_mem_addr = {:X}".format(free_mem_addr))

        if need_to_hook_atoi:
            # Custom version of the default atoi SimProcedure
            class my_atoi(simuvex.SimProcedure):
                def run(self, s, special_addrs=None, added_constraints=None):
                    self.argument_types = {0: self.ty_ptr(SimTypeString())}
                    self.return_type = SimTypeInt(self.state.arch, True)

                    res_symb_var = claripy.BVS('atoi_ret', self.state.arch.bits)
                    
                    # If the argument is a special constrained variable
                    s_val = self.state.se.any_int(s)
                    if s.concrete and s_val in special_addrs:
                        print("Got a special memory addr: {:X}\n".format(s_val))
                        # Grab the operator and right operand
                        (op, r_opr) = special_addrs[s_val]

                        # Add the constraint of: (return_val `op` r_opr)
                        print("Adding claripy_op_mapping[{}]({}, {})\n".format(op, res_symb_var, r_opr))
                        added_constraints.append(claripy_op_mapping[op](res_symb_var, r_opr))
                    return res_symb_var

            self.plugin.angr_proj.hook_symbol('atoi', angr.Hook(my_atoi, special_addrs=atoi_special_addrs, added_constraints=atoi_added_constraints))


    def perform_opaqueness_checks(self, con_addr_asts, branch_addr, succ_addr, pos_unsat_addr, state, atoi_added_constraints):
        # Phase 1: invariant check
        solver = claripy.Solver()
        solver.add(claripy.Not(con_addr_asts[branch_addr]))
        
        # If the negation is unsatisfiable, the predicate is a tautology!
        if not solver.satisfiable():
            cons_str = self._pretty_constraint_str(con_addr_asts[branch_addr])
            self.log_signal.emit(
                "{:x}: Invariant OP found! succ {:x} unreachable.\n  Constraint: {}\n".format(
                    branch_addr, pos_unsat_addr, cons_str)
            )
            self.result_signal.emit(self.ida_func.startEA, [(branch_addr, 0, cons_str)], [(branch_addr, succ_addr, pos_unsat_addr)], [], False)
            return True

        # Phase 2: contextual check
        # predicate p_n is not a tautology, but it might still be
        # contextually opaque, i.e.: (p_1 && p_2 && ...) -> p_n
        solver = claripy.Solver() # fresh solver

        # This is a bit ugly
        # sorted list of conditions, filtered on addr <= branch_addr
        prev_conds = list(zip(*sorted(filter(
                        lambda (x,_): x <= branch_addr,
                        con_addr_asts.items()),
                        key=operator.itemgetter(0)))[1])

        # If no previous conditions AND no extra added constraints
        if len(prev_conds) < 1 and self.ida_func.startEA not in self.plugin.extra_constraints:
            self.log_signal.emit("{:x}: No previous conditions, can't be contextual.\n".format(branch_addr))
            return False

        # Check if AND(prev_conds[:-1]) -> prev_conds[-1]
        cond_conj = claripy.And(*(prev_conds[:-1] + [claripy.Not(prev_conds[-1])]))
        self.log_signal.emit("prev_conds[:-1] = {}".format(prev_conds[:-1]))
        self.log_signal.emit("claripy.Not(prev_conds[-1]) = {}".format(claripy.Not(prev_conds[-1])))

        # Make sure to add any extra user-added constraints to the solver
        self.add_extra_constraints(solver, state)

        # If we have extra atoi-constraints, add to conjunction
        for con in atoi_added_constraints:
            self.log_signal.emit("Adding extra atoi constraint: {}".format(con))
            cond_conj = claripy.And(cond_conj, con)

        solver.add(cond_conj)

        # Is it satisfiable?
        self.log_signal.emit("Solver constraints: {}".format(solver.constraints))
        if not solver.satisfiable():
            #set_block_color(pos_unsat_addr, 0xFFFF00)
            self.log_signal.emit("cond_conj = {}".format(cond_conj))
            cons_str = self._pretty_constraint_str(cond_conj)
            self.log_signal.emit("{:x}: Contextual OP found! succ {:x} unreachable.\n  Constraint: {}\n".format(
                branch_addr, pos_unsat_addr, cons_str)
            )
            self.result_signal.emit(self.ida_func.startEA, [(branch_addr, 1, cons_str)], [], [(branch_addr, succ_addr, pos_unsat_addr)], False)
            return True
        else:
            self.log_signal.emit("{:x}: Not a contextual OP, context: {}.\n".format(branch_addr, prev_conds))
            return False


    def check_opacity(self, branches):
        # Shorthands
        proj = self.plugin.angr_proj

        simuvex_options_add = {
            simuvex.o.CONSTRAINT_TRACKING_IN_SOLVER,
            #simuvex.o.OPTIMIZE_IR,
            simuvex.o.SIMPLIFY_EXPRS,
            simuvex.o.SIMPLIFY_CONSTRAINTS,
            simuvex.o.SIMPLIFY_MEMORY_WRITES,
            simuvex.o.SIMPLIFY_REGISTER_WRITES
        }
        simuvex_options_remove = {
            simuvex.o.LAZY_SOLVES # TODO: this needs to be a setting. Removing it usually improves speed by a lot, but sometimes doesn't
        }

        # Make a blank state and path at the start of the current function
        st = proj.factory.blank_state(
            addr=self.ida_func.startEA,
            add_options=simuvex_options_add,
            remove_options=simuvex_options_remove
        )

        # Optionally make global vars symbolic
        self.make_global_vars_symbolic(st)

        # Optionally set up special constraints for atoi-on-string-array
        atoi_added_constraints = [] # Will be filled
        self.setup_argv_atoi_constraints(st, atoi_added_constraints)

        self.add_custom_hooks()

        # Initial path
        path = proj.factory.path(st)

        # Lists of tuples of: (branch_addr, succ_addr, pos_unsat_addr)
        found_any_op = False
        found_op_branches = []

        # TODO: this assumes that `succ_addr` can only be reached through `branch_addr`

        # For every branch given:
        for (branch_addr, succ_addr, pos_unsat_addr) in branches:
            if self.plugin.stop_analysis:
                break

            # If we already found one for this addr in this run, skip
            if branch_addr in found_op_branches:
                continue

            # If the possible unsat successor has other predecessors which are not (possibly backedges), ignore
            # TODO: this is a heuristic! implement actual backedge check
            other_non_backedge_preds_of_unsat_succ = filter(lambda p: p < pos_unsat_addr, self.ida_func.preds(pos_unsat_addr))
            if len(other_non_backedge_preds_of_unsat_succ) > 1:
                continue

            # Empty any collected atoi extra constraints because
            # this will be filled again by our hooked atoi at the next explore()
            del atoi_added_constraints[:]

            self.log_signal.emit("Looking at branch {:x}...".format(branch_addr))

            # Calculate the 'dominator set' of the succ_addr, which we're looking for
            slice_irsb_addrs = list(self.dominator_set(succ_addr))

            # Explore a pathgroup from the start of the function,
            # ignoring anything in the function, but outside the slice
            pathgroup = proj.factory.path_group(path)

            self.log_signal.emit("Exploring pathgroup to find {:x}...".format(succ_addr))

            # Configure exploration techniques TODO: use Director? or LengthLimiter?
            #et_limiter = angr.exploration_techniques.looplimiter.LoopLimiter(count=1, discard_stash='spinning')
            #pathgroup.use_technique(et_limiter)
            #et_threading = angr.exploration_techniques.looplimiter.Threading(threads=4)
            #pathgroup.use_technique(et_threading)

            # TODO: right now we only avoid unvisited blocks in the current
            # function. Is that correct?
            # TODO: make sure path goes through the parent branch block?
            pathgroup.explore(
                find=lambda p: (
                    (p.addr == succ_addr) or
                    self.plugin.stop_analysis
                    ),
                avoid=lambda p: (
                        p.addr >= self.ida_func.startEA and
                        p.addr < self.ida_func.endEA and
                        p.addr not in slice_irsb_addrs
                    ),
                num_find=1, # How many paths to try to find at most?
                n=SYMBOLIC_MAX_ITERATIONS #  Max amount of iterations.
            )

            # If we 'found' a path because of `stop_analysis`, break
            if self.plugin.stop_analysis:
                break

            self.log_signal.emit("Done exploring pathgroup")

            # Merge all found paths # TODO: check if this works well
            # TODO: instead of merging, make sure opacity holds for every path!
            #pathgroup.merge(stash="found")

            if len(pathgroup.found) == 0:
                if len(pathgroup.unsat) > 0 and (pathgroup.unsat[0].addr == succ_addr or pathgroup.unsat[0].addr == pos_unsat_addr):
                    # Deemed unsatisfiable already..
                    path_found = pathgroup.unsat[0]
                else:
                    self.log_signal.emit("{:x}: No path to branch found... bug? pg = {}, slice_irsb_addrs = {}\n".format(branch_addr, pathgroup, map(hex,slice_irsb_addrs)))
                    self.plugin.pg = pathgroup # TODO: remove, for debugging only
                    continue
            else:
                # Only one was found
                path_found = pathgroup.found[0]

            # TODO: actually continue processing here and invert conditions?
            #if path_found.addr == pos_unsat_addr:
            #    continue

            # Grab the conditions along the path
            # Filter out actions where .condition is None for things like the setz instruction
            con_actions = filter(lambda x: x.type == 'exit' and x.exit_type == 'conditional' and x.condition is not None, list(path_found.actions))

            # Make a list of IDA basic-block addresses hit along the path
            path_addr_trace = filter(lambda x: x != None, map(
                lambda x: self.ida_func.addr_to_cb_start_ea(x),
                list(path_found.addr_trace) + [path_found.addr]
            ))

            # For every added constraint along the path, store it in a dict, mapping
            # the addr of the IDA BB containing the condition to the constraint AST
            con_addr_asts = dict()
            for c in con_actions:
                # The addr of the IDA basic-block that contains the branch
                con_bbl_addr = self.ida_func.addr_to_cb_start_ea(c.ins_addr)

                # TODO: fixme, symbolic target will mess this up
                if not c.target.ast.concrete:
                    continue

                # The (IDA BB) target taken when the condition holds
                con_target_addr = self.ida_func.addr_to_cb_start_ea(c.target.ast.args[0])

                # If that target is not the target that was taken in the path,
                # invert the AST so it always represents the branch that was taken
                # (this is needed because vex IL sometimes flips the original condition)
                if not contains_sublist(path_addr_trace, [con_bbl_addr, con_target_addr]):
                    con_addr_asts[con_bbl_addr] = claripy.Not(c.condition.ast)
                else:
                    con_addr_asts[con_bbl_addr] = c.condition.ast

            # make sure a condition was actually seen in this block
            if branch_addr not in con_addr_asts:
                self.log_signal.emit("{:x}: No condition found\n".format(branch_addr))
                self.plugin.pg = pathgroup # TODO: remove, for debugging only
                continue


            # Perform the actual opaqueness checks!
            found_op = self.perform_opaqueness_checks(
                con_addr_asts,  # The constraint ASTS indexed by basic block addr
                branch_addr,    # The addr of the branching block we're looking at
                succ_addr,      # Non-opaque successor block addr
                pos_unsat_addr, # Possibly opaque successor block addr
                path_found.state, # The state of the path that was found
                atoi_added_constraints # Extra atoi-argv constraints
            )

            # An opaque predicate was found
            if found_op:
                found_op_branches.append(branch_addr)
                found_any_op = True

        return found_any_op


    def run(self):
        # Make sure we have a CFG built
        build_cfg(self.plugin, self.ida_func, self.log_signal)

        try:
            # Find branches along the given trace
            branches = self.find_branches()

            # Duplicate the branches array but with the two successors
            # swapped, for example for cases where the concrete trace
            # takes a supposed-to-be-unsat branch.
            branches = flatten_list([[(b,s1,s2), (b,s2,s1)] for (b,s1,s2) in branches])

            self.log_signal.emit("Branches: {}".format(branches))

            # For each branch, check its opacity
            self.check_opacity(branches)
        except:
            import traceback
            self.log_signal.emit(traceback.format_exc())

        
        self.result_signal.emit(self.ida_func.startEA, [], [], [], True)
        self.log_signal.emit("Analysis done")
        self.plugin.stop_analysis = False


class UnreachableCodePatcher(QObject):
    """
    'Patches' away unreachable code, as specified by code-block colors.
    This is done by fully replacing all instructions in a basic-block
    which is unreachable by NOP instructions, and also replacing all
    conditional jumps to unreachable code-blocks with NOP instructions.
    
    This is a worker class, meant to be ran inside its own QThread.
    """

    log_signal = pyqtSignal(str)

    def __init__(self, plugin):
        QObject.__init__(self)
        self.plugin = plugin

    def run(self):
        # HACK: Switch to flat view first, to fix weird behavior?..
        #idaapi.set_view_renderer_type(idaapi.get_current_viewer(), idaapi.TCCRT_FLAT)
        set_flat_view()
        QThread.msleep(500)

        #nop_instr_bytes = "\x90"
        nop_instr_bytes = self.plugin.angr_proj.arch.nop_instruction
        
        # All the colors that signify unreachable blocks
        unreachable_cols = [
            col_t2ida(self.plugin.col_unreachable),
            col_t2ida(self.plugin.col_invariant),
            col_t2ida(self.plugin.col_contextual)
        ]

        f = sark.Function()
        f_orig_end = f.endEA
        f_orig_start = f.startEA

        # list of (addr, size) tuples to patch with NOP
        patch_list = []

        blocks = get_all_blocks_of_color(f, unreachable_cols)
        for block in blocks:
            # TODO: look at more than first pred
            pred = next(block.preds())

            blocksize = (block.endEA - block.startEA)

            # If the predecessor is not unreachable (i.e. an OP)
            if pred.color not in unreachable_cols:
                pred_succs = list(pred.succs())
                if len(pred_succs) != 2:
                    break

                # This turns out to always be the order in IDA.. (TODO: really ALWAYS?)
                [red_succ, green_succ] = pred_succs 
                
                # If the edge to this block was green..
                if green_succ.startEA == block.startEA:
                    # We are the green successor, so there was a jump to here
                    # patch out the jump statement to NOP: jump is never taken anyway
                    cond_jmp_line = list(pred.lines)[-1]
                    patch_list.append((cond_jmp_line.startEA, cond_jmp_line.size))

                    # Mark area as unknown
                    #idc.MakeUnknown(block.startEA, blocksize, idc.DOUNK_SIMPLE)


                    # Patch away the instructions
                    patch_list.append((block.startEA, blocksize))

                else:
                    # We're the red successor: we always get jumped over
                    # TODO: patch conditional to unconditional jump?

                    # Patch away the instructions
                    patch_list.append((block.startEA, blocksize))

                    # Mark area as unknown
                    #idc.MakeUnknown(block.startEA, blocksize, idc.DOUNK_SIMPLE)
            else:
                # Predecessor is also unreachable

                # Mark area as unknown
                #idc.MakeUnknown(block.startEA, blocksize, idc.DOUNK_SIMPLE)
                patch_list.append((block.startEA, blocksize))

            # refresh colors, hacky
            #pred.color = pred.color
            #block.color = block.color

            # Mark area as unknown
            #idc.MakeUnknown(block.startEA, blocksize, idc.DOUNK_SIMPLE)
        

        # Perform all patches at once
        for (patch_addr, patch_size) in patch_list:
            patch_bytes(patch_addr, (patch_size / len(nop_instr_bytes)) * nop_instr_bytes)


        # HACK: Switch back to graph view
        #idaapi.set_view_renderer_type(idaapi.get_current_viewer(), idaapi.TCCRT_GRAPH)
        QThread.msleep(500)
        set_graph_view()
        #QThread.msleep(500)

        # Fix graph layout
        fix_graph_layout()

        # Recover original function end
        QThread.msleep(500)
        analyze_area(f_orig_start, f_orig_end)
        QThread.msleep(500)
        set_func_end(f_orig_start, f_orig_end)
        #QThread.msleep(100) # HACK: this delay seems to be needed for the ui to catch up
        #idc.SetFunctionEnd(f_orig_start, f_orig_end)
