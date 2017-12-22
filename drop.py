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

import os, sys
from os.path import isfile

import idaapi, idautils, idc
from idaapi import PluginForm
import sark

import angr

from drop import *

DEFAULT_BITNESS = 32

class DropHooks(idaapi.UI_Hooks):
    def __init__(self, plugin):
        self.plugin = plugin
        idaapi.UI_Hooks.__init__(self)

    def database_inited(self, is_new_db, idc_script):
        # A file was loaded, reset vars
        self.plugin.filename = idaapi.get_input_file_path()
        self.plugin.cfg = None
        self.plugin.angr_proj = None
        self.plugin.global_vars = None
        self.plugin.opaque_predicates = dict()
        self.plugin.extra_constraints = dict()
        self.plugin.symbolic_vars = dict()

        # Check if it (still) exists
        if not isfile(self.plugin.filename):
            print("### Drop error: original input file no longer exists, unable to load it into angr. ###")
            return

        # Load the file into angr
        try:
            # This is a bit inefficient, but figure out if it's PIC by loading twice
            p = angr.Project(self.plugin.filename, load_options={'auto_load_libs': False})
            if p.loader.main_bin.pic:
                # Load with IDA's imagebase as base_addr
                base_addr = idaapi.get_imagebase()
            else:
                # Load with 0 as base_addr
                base_addr = 0
            del p
            self.plugin.angr_proj = angr.Project(self.plugin.filename,
                load_options={'auto_load_libs': False, 'main_opts': {
                    'custom_base_addr': base_addr}})

            # get and store the file bitness
            # Don't use idaapi.get_inf_structure().is_32bit(), it will give True for MIPS64...
            self.plugin.bitness = self.plugin.angr_proj.arch.bits

            # Save the list of all recognized variables in .bss, .data and .rodata (TODO: why these? any others?)
            # TODO: Other segments as well?
            self.plugin.global_vars = [var for s in sark.segments() for var in get_segment_names(s) if s.name in [".bss", ".data", ".rodata"]]
            print("### Loaded file into angr succesfully! ###")
        except:
            import traceback
            print("ERROR: Failed to load file into angr: {}".format(traceback.format_exc()))


class DropPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC # Load plugin before a file is loaded
    comment = "Drop: Interactive deobfuscation"
    help = ""
    wanted_name = "Drop: Interactive deobfuscation"
    wanted_hotkey = "Alt-F6"

    # Settings, TODO: move into a Settings class?
    col_neutral     = (0xFF, 0xFF, 0xFF) # white
    col_visited     = (0x80, 0xFF, 0x80) # 0x80FF80  # green
    col_unreachable = (0xFF, 0x80, 0xFF) # 0xFF80FF  # pink / purple
    col_invariant   = (0xFF, 0xFF, 0x80) # 0x80FFFF  # yellow
    col_contextual  = (0x80, 0xFF, 0xFF) # 0xFFFF80  # cyan

    # Set this flag to stop any ongoing analysis
    stop_analysis = False

    # Project-global vars
    filename = None
    cfg = None
    angr_proj = None
    global_vars = None
    bitness = DEFAULT_BITNESS

    # opaque predicates found (dict[fun_addr] -> set())
    opaque_predicates = dict()

    # collection of added constraints
    extra_constraints = dict()

    # collection of symbolic variables per function
    symbolic_vars = dict()

    # ollection of custom function hooks per function
    function_hooks = dict()

    # Plugin-global vars
    gui = None
    hooks = None
    inited = False

    # TODO: remove, for debugging
    pg = None

    #def __init__(self):
    #    idaapi.plugin_t.__init__(self)
    #    pass

    def init(self):
        if not self.inited:
            # hook the hooks
            self.hooks = DropHooks(self)
            self.hooks.hook()
            self.inited = True

            # For debugging, put a reference to us in __main__
            sys.modules[__name__].deobf = self
            
            print("### Drop: Deobfuscation plugin loaded ###")

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Only show the GUI if an angr project exists
        if not self.angr_proj:
            return

        if not self.gui:
            self.gui = DropGUI(self)
        self.gui.show()
        return

    def term(self):
        self.hooks.unhook()
        pass


def PLUGIN_ENTRY():
    return DropPlugin()
