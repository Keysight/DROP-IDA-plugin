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

import ctypes
import time

# Qt related
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import pyqtSlot, QThread, QEvent
import sip

# IDA related
import idaapi, idautils, idc
from idaapi import PluginForm
import sark

# Other non-builtin packages
import networkx

# Package-local imports
from workers import *

WINDOW_NAME = 'Drop'

# TODO: remove this
MANUAL_CONCRETE_ARGS = True

class DropGUI(PluginForm):

    def __init__(self, plugin):
        PluginForm.__init__(self)
        self.plugin = plugin
        self.current_function = None
        self.refresh_output = False
        self.current_worker_thread = None

    def show(self):
        PluginForm.Show(self, WINDOW_NAME)

        # Set up the refresh timer
        self.timer = QtCore.QTimer(self.parent)
        self.timer.timeout.connect(self.timer_update)
        self.timer.start(250) # every quarter second
        self.current_function = None

    def OnCreate(self, form):
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)

        # Set location and width (TODO: hacky)
        idaapi.set_dock_pos(WINDOW_NAME, 'IDA View-A', idaapi.DP_RIGHT)
        self.parent.parent().setMaximumWidth(500)

        # Populate
        self.populate_form()


    def _make_hline(self):
        hline = QtWidgets.QFrame()
        hline.setFrameShape(QtWidgets.QFrame.HLine)
        hline.setFrameShadow(QtWidgets.QFrame.Sunken)
        return hline


    def populate_form(self):
        # Create layout
        hbox = QtWidgets.QHBoxLayout()
        vbox = QtWidgets.QVBoxLayout()
        #layout.addWidget(QtWidgets.QLabel("Bla"))

        # Basic-block color marking buttons
        #mark_color_hbox = QtWidgets.QHBoxLayout()
        self.btn_mark_neutral = QtWidgets.QPushButton("NEUTRAL");
        self.btn_mark_neutral.setStyleSheet("background-color: rgb({c[0]:d},{c[1]:d},{c[2]:d});".format(c=self.plugin.col_neutral));
        self.btn_mark_neutral.clicked.connect(self.btn_mark_color)
        self.btn_mark_visited = QtWidgets.QPushButton("TRACE");
        self.btn_mark_visited.setStyleSheet("background-color: rgb({c[0]:d},{c[1]:d},{c[2]:d});".format(c=self.plugin.col_visited));
        self.btn_mark_visited.clicked.connect(self.btn_mark_color)
        self.btn_mark_unreachable = QtWidgets.QPushButton("UNREACHABLE");
        self.btn_mark_unreachable.setStyleSheet("background-color: rgb({c[0]:d},{c[1]:d},{c[2]:d});".format(c=self.plugin.col_unreachable));
        self.btn_mark_unreachable.clicked.connect(self.btn_mark_color)
        #mark_color_hbox.addWidget(QtWidgets.QLabel("Mark current CB as:"))
        #mark_color_hbox.addWidget(self.btn_mark_neutral)
        #mark_color_hbox.addWidget(self.btn_mark_visited)
        #mark_color_hbox.addWidget(self.btn_mark_unreachable)

        self.btn_reset_graph = QtWidgets.QPushButton('Reset all block colors of current function')
        self.btn_reset_graph.clicked.connect(self.btn_reset_graph_clicked)

        self.btn_config_settings = QtWidgets.QPushButton('Settings...')
        self.btn_config_settings.clicked.connect(self.btn_config_settings_clicked)

        
        # OP Widgets
        #self.btn_init_angr = QtWidgets.QPushButton('Initialize angr')
        #self.btn_init_angr.clicked.connect(self.btn_init_angr_clicked)

        self.btn_stop_thread = QtWidgets.QPushButton('Try to interrupt analysis (might crash IDA)')
        self.btn_stop_thread.clicked.connect(self.btn_stop_thread_clicked)
        self.btn_show_angr_graph = QtWidgets.QPushButton('angr CFG')
        self.btn_show_angr_graph.clicked.connect(self.btn_show_angr_graph_clicked)



        self.btn_concrete = QtWidgets.QPushButton('concrete trace...')
        self.btn_concrete.clicked.connect(self.btn_concrete_clicked)

        self.btn_opaque = QtWidgets.QPushButton('along trace')
        self.btn_opaque.clicked.connect(self.btn_opaque_clicked)
        self.btn_branch_opaque = QtWidgets.QPushButton('in current block')
        self.btn_branch_opaque.clicked.connect(self.btn_branch_opaque_clicked)


        self.btn_propagate = QtWidgets.QPushButton('Propagate unreachability')
        self.btn_propagate.clicked.connect(self.btn_propagate_clicked)
        self.btn_nop = QtWidgets.QPushButton('NOP unreachable code')
        self.btn_nop.clicked.connect(self.btn_nop_clicked)


        self.list_constraints = QtWidgets.QListWidget()
        self.list_symbolic = QtWidgets.QListWidget()
        self.list_hooks = QtWidgets.QListWidget()

        self.btn_add_constraint = QtWidgets.QPushButton('Add...')
        self.btn_add_constraint.clicked.connect(self.btn_add_constraint_clicked)

        self.btn_del_constraint = QtWidgets.QPushButton('Delete')
        self.btn_del_constraint.clicked.connect(self.btn_del_constraint_clicked)
        self.btn_del_constraint.setEnabled(False)

        self.btn_add_symbolic = QtWidgets.QPushButton('Add...')
        self.btn_add_symbolic.clicked.connect(self.btn_add_symbolic_clicked)

        self.btn_del_symbolic = QtWidgets.QPushButton('Delete')
        self.btn_del_symbolic.clicked.connect(self.btn_del_symbolic_clicked)
        self.btn_del_symbolic.setEnabled(False)

        self.btn_add_hook = QtWidgets.QPushButton('Add...')
        self.btn_add_hook.clicked.connect(self.btn_add_hook_clicked)

        self.btn_del_hook = QtWidgets.QPushButton('Delete')
        self.btn_del_hook.clicked.connect(self.btn_del_hook_clicked)
        self.btn_del_hook.setEnabled(False)


        self.table_ops_found = QtWidgets.QTableWidget(0,3)
        self.table_ops_found.setHorizontalHeaderLabels(['block addr', 'type', 'condition'])
        self.table_ops_found.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows);
        self.table_ops_found.doubleClicked.connect(self.table_ops_doubleclicked)
        self.table_ops_found.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)

        self.btn_clear_ops = QtWidgets.QPushButton('Clear table')
        self.btn_clear_ops.clicked.connect(self.btn_clear_ops_clicked)


        # Log stuff
        self.output = QtWidgets.QTextEdit("")
        self.output.setReadOnly(True)


        # Step 1
        gbox_step1 = QtWidgets.QGroupBox("Step 1: Find candidate branches")
        hb1 = make_hbox(
            "manually mark current block as: ",
            self.btn_mark_visited,
            self.btn_mark_neutral
        )
        hb2 = make_hbox(
            "or automatically mark blocks along a: ",
            self.btn_concrete
        )
        self.btn_concrete.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        vbox_gbox_step1 = make_vbox(
            hb1,
            hb2
        )
        gbox_step1.setLayout(vbox_gbox_step1)


        # Step 2
        gbox_step2 = QtWidgets.QGroupBox("Step 2: Detect opaque predicates")
        self.checkbox_all_symbolic = QtWidgets.QCheckBox("all globals symbolic")
        self.checkbox_all_symbolic.setChecked(False)
        self.checkbox_all_symbolic.toggled.connect(self.checkbox_all_symbolic_toggled)
        # Additional inputs
        vbox_extra_input = make_hbox(
            make_vbox(
                "Extra constraints:",
                self.list_constraints,
                make_hbox(self.btn_add_constraint, self.btn_del_constraint)
            ),
            make_vbox(
                "Symbolic variables:",
                self.list_symbolic,
                self.checkbox_all_symbolic,
                make_hbox(self.btn_add_symbolic, self.btn_del_symbolic)
            ),
            make_vbox(
                "Hooked functions:",
                self.list_hooks,
                make_hbox(self.btn_add_hook, self.btn_del_hook)
            )
        )
        vbox_gbox_step2 = make_vbox(
            vbox_extra_input,
            self._make_hline(),
            make_hbox(
                "Find opaque predicates: ",
                self.btn_opaque,
                " or ",
                self.btn_branch_opaque
            )
        )
        self.btn_opaque.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.btn_branch_opaque.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        gbox_step2.setLayout(vbox_gbox_step2)


        # Step 3
        gbox_step3 = QtWidgets.QGroupBox("Step 3: Dead code removal")
        vbox_gbox_step3 = make_vbox(
            make_hbox(
                "manually mark current block as: ",
                self.btn_mark_unreachable
            ),
            make_hbox(
                "or",
                self.btn_propagate,
                "and then",
                self.btn_nop
            )
        )
        self.btn_mark_unreachable.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.btn_propagate.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.btn_nop.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        gbox_step3.setLayout(vbox_gbox_step3)


        # Add groupboxes to super vbox
        vbox.addWidget(gbox_step1)
        vbox.addWidget(gbox_step2)
        vbox.addWidget(gbox_step3)

        # Add other widgets
        vbox.addLayout(make_hbox(
            "Opaque predicates found (doubleclick to jump to condition):",
            self.btn_clear_ops
        ))
        vbox.addWidget(self.table_ops_found)

        # Add some extraneous buttons
        vbox.addLayout(make_vbox(
            make_hbox(
                self.btn_stop_thread,
                self.btn_show_angr_graph,
                self.btn_config_settings
            ),
            self.btn_reset_graph
        ))


        #vbox.addStretch(1)
        #tab_op.addWidget(self._make_hline())

        # Final hbox to stretch everything out horizontally
        hbox.addLayout(vbox)
        #hbox.addStretch(1)
        self.parent.setLayout(hbox)


    def timer_update(self):
        """
        Called everytime the timer times out. Refresh displayed info.
        """

        try:
            f = sark.Function()
            fun_addr = f.startEA
        except:
            # Probably not in a function
            return

        # Do nothing if the current function didn't change
        # and a refresh was not requested
        if self.current_function == fun_addr and not self.refresh_output:
            return

        fun_name = f.name
        if self.plugin.angr_proj and self.plugin.angr_proj.kb.functions:
            cfg_made = self.plugin.angr_proj.kb.functions.function(fun_addr) is not None
        else:
            cfg_made = False
        extra_cons = None
        ops_found = None

        # Clear the constraint list in GUI
        while self.list_constraints.count() > 0:
            self.list_constraints.takeItem(0)
        self.btn_del_constraint.setEnabled(False)

        # If constraint set exists and is not empty
        cons_to_str = lambda (opr1, op, opr2): "{} {} {}".format(opr2str(opr1), op, opr2str(opr2))
        if fun_addr in self.plugin.extra_constraints and self.plugin.extra_constraints[fun_addr]:
            # Add new items back to GUI list
            for cons in self.plugin.extra_constraints[fun_addr]:
                item = QtWidgets.QListWidgetItem(cons_to_str(cons), self.list_constraints)
                item.setData(QtCore.Qt.UserRole, cons)
                self.list_constraints.addItem(item)
                self.btn_del_constraint.setEnabled(True)

        # Clear the symbolic var list in GUI
        while self.list_symbolic.count() > 0:
            self.list_symbolic.takeItem(0)
        self.btn_del_symbolic.setEnabled(False)

        # If symbolic var set exists and is not empty
        symb_var_to_str = lambda symb_var: "0x{:X}".format(symb_var) # TODO get IDA symbol name?
        if fun_addr in self.plugin.symbolic_vars and self.plugin.symbolic_vars[fun_addr]:
            # Add new items back to GUI list
            for symb_var in self.plugin.symbolic_vars[fun_addr]:
                item = QtWidgets.QListWidgetItem(symb_var_to_str(symb_var), self.list_symbolic)
                item.setData(QtCore.Qt.UserRole, symb_var)
                self.list_symbolic.addItem(item)
                self.btn_del_symbolic.setEnabled(True)


        # Clear the hook list in GUI
        while self.list_hooks.count() > 0:
            self.list_hooks.takeItem(0)
        self.btn_del_hook.setEnabled(False)

        # If hook set exists and is not empty
        hook_to_str = lambda hook: "0x{:X} -> {}{}".format(hook[0], hook[1], (" ("+hook[2]+")") if hook[2] else "")
        if fun_addr in self.plugin.function_hooks and self.plugin.function_hooks[fun_addr]:
            # Add new items back to GUI list
            for hook in self.plugin.function_hooks[fun_addr]:
                item = QtWidgets.QListWidgetItem(hook_to_str(hook), self.list_hooks)
                item.setData(QtCore.Qt.UserRole, hook)
                self.list_hooks.addItem(item)
                self.btn_del_hook.setEnabled(True)
        

        # Clear OP table
        self.table_ops_found.setRowCount(0)

        # If OP set exists and is not empty
        if fun_addr in self.plugin.opaque_predicates and self.plugin.opaque_predicates[fun_addr]:
            # (addr, type, str)
            #ops_found = "\n" + "\n".join(map(
            #    lambda (a, t, s): "  0x{:x}: {}: {}".format(a, "invariant" if t == 0 else "contextual",
            #        s if s is not "True" else "True (simplified away by angr)"),
            #    self.plugin.opaque_predicates[fun_addr]
            #))

            # Add new items back to GUI table
            for (op_addr, op_type, op_str) in self.plugin.opaque_predicates[fun_addr]:
                row_count = self.table_ops_found.rowCount()
                self.table_ops_found.insertRow(row_count)
                self.table_ops_found.setItem(row_count, 0, QtWidgets.QTableWidgetItem("{:X}".format(op_addr)))
                self.table_ops_found.setItem(row_count, 1, QtWidgets.QTableWidgetItem("invariant" if op_type == 0 else "contextual"))

                if op_str == "True":
                    op_str = "True (simplified away)"

                item_constraint = QtWidgets.QTableWidgetItem(op_str)
                item_constraint.setToolTip(op_str)
                self.table_ops_found.setItem(row_count, 2, item_constraint)

                # Background color
                col_tuple = self.plugin.col_invariant if op_type == 0 else self.plugin.col_contextual
                qcolor = QtGui.QColor(col_tuple[0], col_tuple[1], col_tuple[2])
                self.table_ops_found.item(row_count, 0).setBackground(qcolor)
                self.table_ops_found.item(row_count, 1).setBackground(qcolor)
                self.table_ops_found.item(row_count, 2).setBackground(qcolor)


        new_text = (
            "Current function: {} (0x{:x})\n".format(fun_name, fun_addr) +
            "angr CFG generated: {}\n".format("Yes" if cfg_made else "No") +
            "Opaque predicates found: {}\n".format("-" if not ops_found else ops_found)
        )
        
        self.output.setText(new_text)
        self.current_function = fun_addr
        self.refresh_output = False


    def spawn_worker_thread(self, worker, **signals):
        # Setup worker and its thread
        thread = QThread(self.parent)
        thread.setTerminationEnabled(True)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        thread.worker = worker # TODO: needed?

        # Connect log and any extra signals
        worker.log_signal.connect(self.log_append)
        for signal_name in signals:
            getattr(worker, signal_name).connect(signals[signal_name])

        thread.start()

        self.current_worker_thread = thread

    def log_append(self, s):
        idaapi.msg(s + "\n")

    def concrete_trace_results(self, addr_trace):
        # Color all blocks along the trace as 'visited'
        for addr in addr_trace:
            set_block_color(addr, col_t2ida(self.plugin.col_visited))
        self.btn_concrete.setEnabled(True)

    def opaque_results(self, f_start_ea, opaque_preds, opaque_invariant, opaque_contextual, done=False):
        # Save the results
        if opaque_preds:
            if f_start_ea not in self.plugin.opaque_predicates:
                self.plugin.opaque_predicates[f_start_ea] = set()
            self.plugin.opaque_predicates[f_start_ea] |= set(opaque_preds)

        # Color the appropriate blocks
        for (branch_addr, succ_sat, succ_unsat) in opaque_invariant:
            set_block_color(succ_unsat, col_t2ida(self.plugin.col_invariant))

        for (branch_addr, succ_sat, succ_unsat) in opaque_contextual:
            set_block_color(succ_unsat, col_t2ida(self.plugin.col_contextual))

        if done:
            self.btn_opaque.setEnabled(True)
            self.btn_branch_opaque.setEnabled(True)
            
        self.refresh_output = True

    def unreachable_results(self, unreachable_blocks):
        for addr in unreachable_blocks:
            set_block_color(addr, col_t2ida(self.plugin.col_unreachable))

        self.btn_propagate.setEnabled(True)
        self.refresh_output = True

 
    def btn_mark_color(self):
        sender = self.parent.sender()
        cb = sark.CodeBlock()

        if sender is self.btn_mark_neutral:
            cb.color = col_t2ida(self.plugin.col_neutral)
        elif sender is self.btn_mark_visited:
            cb.color = col_t2ida(self.plugin.col_visited)
        elif sender is self.btn_mark_unreachable:
            cb.color = col_t2ida(self.plugin.col_unreachable)


    def checkbox_all_symbolic_toggled(self):
        if self.checkbox_all_symbolic.isChecked():
            # Deactivate individual global variable input
            self.list_symbolic.setEnabled(False)
            self.btn_add_symbolic.setEnabled(False)
            self.btn_del_symbolic.setEnabled(False)
        else:
            # Activate individual global variable input
            self.list_symbolic.setEnabled(True)
            self.btn_add_symbolic.setEnabled(True)
            self.btn_del_symbolic.setEnabled(True)


    def btn_stop_thread_clicked(self):
        if self.current_worker_thread and self.current_worker_thread.isRunning():
            self.plugin.stop_analysis = True
            # woow hacky
            try:
                import z3
                frames = sys._current_frames().values()
                for f in frames:
                    if 'a0' in f.f_locals:
                        #print("Found Z3 frame: {}".format(f.f_code))
                        c = f.f_locals['a0']
                        ctx = z3.main_ctx()
                        ctx.ctx = c
                        ctx.interrupt()
                        break
                self.current_worker_thread.terminate()
            except:
                print("Ex: {}, {}".format(sys.exc_info(), frame.f_code))
            #print("Bla 2")
            if self.current_worker_thread.isRunning():
                print("Termination failed")
            else:
                print("Terminated thread")


    def btn_show_angr_graph_clicked(self):
        # Assume angr is loaded
        def mapping(node):
            b = self.plugin.angr_proj.factory.block(node.addr)
            return str(b.capstone)

        try:
            graph = self.plugin.cfg.functions[self.current_function].graph
            graph2 = networkx.relabel_nodes(graph, mapping)
            viewer = sark.ui.NXGraph(graph2, title="angr graph", padding=0)
            viewer.Show()
        except:
            print("ERROR: {}".format(sys.exc_info()))

    def btn_reset_graph_clicked(self):
        reset_block_colors(sark.Function())

    def btn_clear_ops_clicked(self):
        self.plugin.opaque_predicates[self.current_function] = set()
        self.refresh_output = True

    def btn_concrete_clicked(self):
        self.btn_concrete.setEnabled(False)

        if not MANUAL_CONCRETE_ARGS:
            # Get current function's arguments and ask for concrete values
            f_type = get_func_type(self.current_function)
            if not f_type:
                self.btn_concrete.setEnabled(True)
                return
        else:
            # Ask for the number of arguments
            val, ok = QtWidgets.QInputDialog.getInt(None,"param input","How many arguments should we pass?", 1)
            if not ok or val < 0:
                self.log_append("Cancelled.")
                self.btn_concrete.setEnabled(True)
                return
            # Set types to all int, TODO: fix
            f_type = ("void", ["int"] * val)

        self.log_append("Function type: {}".format(f_type))
        params = []
        for idx, arg_type in enumerate(f_type[1]):
            #val = asklong(42, "Give a value for argument {} of type '{}'".format(idx+1, arg_type))
            val, ok = QtWidgets.QInputDialog.getText(None,"param input","Give a value for argument {}. Enclose strings with double quotes.".format(idx+1, arg_type))
            if not ok:
                self.log_append("Cancelled.")
                self.btn_concrete.setEnabled(True)
                return
            params.append(val)

        # Spawn the worker thread
        f = IDAFunctionCodeBlocks(sark.Function())
        self.spawn_worker_thread(
            ConcreteRunner(self.plugin, f, arg_vals=params),
            result_signal=self.concrete_trace_results
        )

    def btn_opaque_clicked(self):
        self.btn_opaque.setEnabled(False)

        # Retrieve the addr_trace from colored code-blocks
        f = IDAFunctionCodeBlocks(sark.Function())
        cbs = get_all_blocks_of_color(f, col_t2ida(self.plugin.col_visited))
        addr_trace = [cb.startEA for cb in cbs]

        # Spawn the worker thread
        self.spawn_worker_thread(
            OpaquePredicateFinder(self.plugin, f, addr_trace, self.checkbox_all_symbolic.isChecked()),
            result_signal=self.opaque_results
        )

    def btn_branch_opaque_clicked(self):
        self.btn_branch_opaque.setEnabled(False)
        
        # Only have it look at the currently selected code-block
        addr_trace = [get_current_codeblock().startEA]

        f = IDAFunctionCodeBlocks(sark.Function())
        self.spawn_worker_thread(
            OpaquePredicateFinder(self.plugin, f, addr_trace, self.checkbox_all_symbolic.isChecked()),
            result_signal=self.opaque_results
        )

    def btn_propagate_clicked(self):
        self.btn_propagate.setEnabled(False)

        self.spawn_worker_thread(
            UnreachabilityPropagator(self.plugin),
            result_signal=self.unreachable_results
        )

    def btn_nop_clicked(self):
        self.spawn_worker_thread(UnreachableCodePatcher(self.plugin))


    def btn_config_settings_clicked(self):
        global CONCRETE_MAX_ITERATIONS, SYMBOLIC_MAX_ITERATIONS
        dia = SettingsDialog(CONCRETE_MAX_ITERATIONS, SYMBOLIC_MAX_ITERATIONS)
        if dia.exec_() == QtWidgets.QDialog.Accepted:
            (CONCRETE_MAX_ITERATIONS, SYMBOLIC_MAX_ITERATIONS) = dia.get_value()

    def btn_add_constraint_clicked(self):
        dia = AddConstraintDialog()
        if dia.exec_() == QtWidgets.QDialog.Accepted:
            (exp1, op, exp2) = dia.get_value()
            if not op:
                self.log_append("ERROR: Invalid operator")
                return

            # Try to parse input
            exp1_parsed = try_parse_ida_ident(exp1)
            exp2_parsed = try_parse_ida_ident(exp2)

            if not exp1_parsed or not exp2_parsed:
                self.log_append("ERROR: Couldn't parse an operand as a valid expression")
                return

            #self.log_append("{} {} {}".format(exp1_parsed, op, exp2_parsed))

            # Add it to the list for this function
            if self.current_function not in self.plugin.extra_constraints:
                self.plugin.extra_constraints[self.current_function] = []
            self.plugin.extra_constraints[self.current_function].append((exp1_parsed, op, exp2_parsed))

            # Refresh the output display
            self.refresh_output = True


    def btn_del_constraint_clicked(self):
        # Delete the currently selected constraint
        for item in self.list_constraints.selectedItems():
            # Delete from set
            self.plugin.extra_constraints[self.current_function].remove(item.data(QtCore.Qt.UserRole))
            # Delete from GUI
            self.list_constraints.takeItem(self.list_constraints.row(item))
        self.refresh_output = True


    def btn_add_symbolic_clicked(self):
        dia = AddSymbolicVarDialog() # TODO: also ask for var type / size
        if dia.exec_() == QtWidgets.QDialog.Accepted:
            symb_var_str = dia.get_value()

            # Try to parse input
            parse_res = try_parse_ida_ident(symb_var_str)
            if parse_res == False:
                self.log_append("ERROR: Couldn't parse input as a symbol name or address")
                return

            (symb_type, symb_var_addr) = parse_res
            if symb_type != 3 or not symb_var_addr:
                self.log_append("ERROR: Couldn't parse input as a symbol name or address")
                return

            if symb_var_addr not in dict(self.plugin.global_vars):
                self.log_append("ERROR: Address {} is not a detected variable: {}".format(symb_var_addr, self.plugin.global_vars.keys()))
                return

            # Add it to the list for this function
            if self.current_function not in self.plugin.symbolic_vars:
                self.plugin.symbolic_vars[self.current_function] = []
            self.plugin.symbolic_vars[self.current_function].append(symb_var_addr)

            # Refresh the output display
            self.refresh_output = True

    def btn_del_symbolic_clicked(self):
        # Delete the currently selected symbolic variable
        for item in self.list_symbolic.selectedItems():
            # Delete from set
            self.plugin.symbolic_vars[self.current_function].remove(item.data(QtCore.Qt.UserRole))
            # Delete from GUI
            self.list_symbolic.takeItem(self.list_symbolic.row(item))
        self.refresh_output = True


    def btn_add_hook_clicked(self):
        dia = AddHookDialog()
        if dia.exec_() == QtWidgets.QDialog.Accepted:
            (fun_addr, hook_text, custom_text) = dia.get_value()

            # Add it to the list for this function
            if self.current_function not in self.plugin.function_hooks:
                self.plugin.function_hooks[self.current_function] = []
            self.plugin.function_hooks[self.current_function].append((fun_addr, hook_text, custom_text))

            # Refresh the output display
            self.refresh_output = True


    def btn_del_hook_clicked(self):
        # Delete the currently selected hook
        for item in self.list_hooks.selectedItems():
            hook = item.data(QtCore.Qt.UserRole)

            # Unhook
            hook_addr = hook[0]
            self.plugin.angr_proj.unhook(hook_addr)

            # Delete from set
            self.plugin.function_hooks[self.current_function].remove(hook)
            # Delete from GUI
            self.list_hooks.takeItem(self.list_hooks.row(item))
        self.refresh_output = True


    def table_ops_doubleclicked(self, index):
        row = index.row()
        print("row = {}".format(row))
        addr = int(self.table_ops_found.item(row, 0).text(), 16)
        print("addr = {}".format(addr))
        idaapi.jumpto(addr)

    def OnClose(self, form):
        if self.current_worker_thread and self.current_worker_thread.isRunning():
            print("A worker is still running...")
            return False
        #self.plugin.Close()
        self.timer.stop()
        # TODO: kill any threads?
        return True


class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, num_c, num_s):
        QtWidgets.QDialog.__init__(self)
        self.result = None

        self.max_concrete_iter = QtWidgets.QLineEdit(str(num_c))
        self.max_symbolic_iter = QtWidgets.QLineEdit(str(num_s))
        btn_ok = QtWidgets.QPushButton("OK")
        btn_ok.clicked.connect(self.btn_ok_clicked)

        vbox = make_vbox(
            make_hbox(
                "Maximum iterations (basic-blocks) during concrete execution",
                self.max_concrete_iter
            ),
            make_hbox(
                "Maximum iterations (basic-blocks) during symbolic execution",
                self.max_symbolic_iter
            ),
            make_hbox(
                btn_ok
            )
        )
        self.setLayout(vbox)

    def btn_ok_clicked(self):
        num_c = self.max_concrete_iter.text()
        num_s = self.max_symbolic_iter.text()
        try:
            num_c = int(num_c)
            num_s = int(num_s)
            if num_c < 1 or num_s < 1:
                raise ValueError()
        except ValueError:
            QtWidgets.QMessageBox.information(None, 'Error','Inputs can only be positive numbers')
            return
        self.result = (num_c, num_s)
        self.accept()

    def get_value(self):
        return self.result


class AddHookDialog(QtWidgets.QDialog):
    list_simprocedures = {
        "No-op": "nop",
        "Return unconstrained": "unconstrained",
        "Return constant word...": "constant",
        #"Redirect control-flow to...": "redirect",
        "Return printable character": "printable_char"
    }

    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        self.result = None
        self.picked_function = None

        buttons_hbox = QtWidgets.QHBoxLayout()

        # Operands
        self.edit = QtWidgets.QLineEdit()

        btn_ok = QtWidgets.QPushButton("OK")
        btn_ok.clicked.connect(self.btn_ok_clicked)
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.btn_cancel_clicked)

        buttons_hbox.addWidget(btn_ok)
        buttons_hbox.addWidget(btn_cancel)

        self.edit_picked_fun = QtWidgets.QLineEdit("<none>")
        self.edit_picked_fun.setDisabled(True)
        btn_pick = QtWidgets.QPushButton("Choose...")
        btn_pick.clicked.connect(self.btn_pick_clicked)
        self.chooser_sim_procedure = QtWidgets.QComboBox()
        self.chooser_sim_procedure.addItems(AddHookDialog.list_simprocedures.keys())
        self.chooser_sim_procedure.currentIndexChanged.connect(self.chooser_selection_changed)

        self.custom_label = QtWidgets.QLabel("")
        self.custom_edit = QtWidgets.QLineEdit("")
        self.custom_label.setVisible(False)
        self.custom_edit.setVisible(False)

        vbox = make_vbox(
            make_hbox(
                "Pick a function to hook: ",
                self.edit_picked_fun,
                btn_pick
            ),
            make_hbox(
                "Choose a predefined hook:",
                self.chooser_sim_procedure
            ),
            make_hbox(
                self.custom_label,
                self.custom_edit
            ),
            buttons_hbox
        )

        self.setLayout(vbox)

    def chooser_selection_changed(self):
        self.custom_edit.setText("")
        sel_sp = AddHookDialog.list_simprocedures[self.chooser_sim_procedure.currentText()]
        if sel_sp == "constant":
            # Show editbox for the value
            self.custom_label.setText("Specify the integer value to return: ")
            self.custom_edit.setText("42")
            self.custom_label.setVisible(True)
            self.custom_edit.setVisible(True)
        elif sel_sp == "redirect":
            # Show editbox for address
            self.custom_label.setText("Specify the address to redirect to: ")
            self.custom_edit.setText("0xDEADBEEF")
            self.custom_label.setVisible(True)
            self.custom_edit.setVisible(True)
        else:
            # Hide editbox
            self.custom_label.setVisible(False)
            self.custom_edit.setVisible(False)



    def btn_pick_clicked(self):
        ida_f = idaapi.choose_func("Pick a function to hook", idaapi.BADADDR)
        func_addr = ida_f.startEA
        func_name = idaapi.get_func_name(func_addr)

        self.picked_function = func_addr
        self.edit_picked_fun.setText("0x{:X} ({})".format(func_addr, func_name))


    def btn_ok_clicked(self):
        if not self.picked_function:
            QtWidgets.QMessageBox.information(None, 'Error','Choose a function to hook')
            return

        if self.custom_edit.isVisible() and len(self.custom_edit.text()) == 0:
            QtWidgets.QMessageBox.information(None, 'Error','Please specify additional information for the hook')
            return

        sp = AddHookDialog.list_simprocedures[self.chooser_sim_procedure.currentText()]
        self.result = (self.picked_function, sp, self.custom_edit.text())

        self.accept()
        return self.result

    def btn_cancel_clicked(self):
        self.reject()

    def get_value(self):
        return self.result


class AddSymbolicVarDialog(QtWidgets.QDialog):
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        self.result = None

        vbox = QtWidgets.QVBoxLayout()
        buttons_hbox = QtWidgets.QHBoxLayout()

        # Operands
        self.edit = QtWidgets.QLineEdit()

        btn_ok = QtWidgets.QPushButton("OK")
        btn_ok.clicked.connect(self.btn_ok_clicked)
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.btn_cancel_clicked)

        buttons_hbox.addWidget(btn_ok)
        buttons_hbox.addWidget(btn_cancel)

        vbox.addWidget(QtWidgets.QLabel("Enter the address or name of a .bss/.data/.rodata variable."))
        vbox.addWidget(self.edit)
        vbox.addLayout(buttons_hbox)

        self.setLayout(vbox)

    def btn_ok_clicked(self):

        self.result = self.edit.text()
        self.accept()
        return self.result

    def btn_cancel_clicked(self):
        self.reject()

    def get_value(self):
        return self.result


class AddConstraintDialog(QtWidgets.QDialog):
    def __init__(self):
        #super(AddConstraintDialog, self).__init__(parent)
        QtWidgets.QDialog.__init__(self)
        self.result = (None,None,None)

        vbox = QtWidgets.QVBoxLayout()
        buttons_hbox = QtWidgets.QHBoxLayout()

        # Operands
        self.edit1 = QtWidgets.QLineEdit()
        self.edit2 = QtWidgets.QLineEdit()

        # Operator selection box
        operators = ["<", ">", "==", "!=", "<=", ">="]
        self.operator = QtWidgets.QComboBox()
        self.operator.addItems(operators)

        


        btn_ok = QtWidgets.QPushButton("OK")
        btn_ok.clicked.connect(self.btn_ok_clicked)
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.btn_cancel_clicked)

        buttons_hbox.addWidget(btn_ok)
        buttons_hbox.addWidget(btn_cancel)

        vbox.addWidget(QtWidgets.QLabel("Enter a new constraint. Example operands:\neax, arg_0, [globalVar], 0xFEEDBEEF, 42"))
        vbox.addWidget(self.edit1)
        vbox.addWidget(self.operator)
        vbox.addWidget(self.edit2)
        vbox.addLayout(buttons_hbox)

        self.setLayout(vbox)
        #self.setGeometry(300, 200, 460, 350)

    def btn_ok_clicked(self):

        self.result = (
            self.edit1.text(),
            self.operator.currentText(),
            self.edit2.text()
        )

        #if self.result == None:
        #    QtWidgets.QMessageBox.information(self, "Error",
        #    "Please enter a valid constraint")
        #    self.reject()
        #    return
        self.accept()
        return self.result

    def btn_cancel_clicked(self):
        self.reject()

    def get_value(self):
        return self.result


