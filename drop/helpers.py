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
import ctypes
import re

# Qt related
from PyQt5.QtCore import QThread
from PyQt5 import QtWidgets

# IDA related
import idaapi
import idautils
import idc
from idaapi import PluginForm
import sark

# Other non-builtin packages
import pycparser

def try_parse_ida_ident(ident):
    """
    Returns a tuple of (type, value):
        (0, addr) -> a memory address
        (1, offs) -> an EBP offset      TODO: arch-independent?
        (2, name) -> a register name
        (3, val)  -> a constant
        (4, s)    -> a string
        (5, (arr, idx))  -> atoi of an array with constant index.
    """
    ident = str(ident)
    if len(ident) == 0:
        return False

    # match things like:
    #  atoi(some_global_var[3])
    #  0x500[1]    (also implicitely means to apply atoi)
    if (ident.find("[") > 0 and ident[-1] == "]") or (ident[:5] == "atoi(" and ident[-2:] == "])"):
        ident = ident.replace("atoi(", "").replace("])","]")
        idx = ident[ident.find("[")+1:-1]
        before_idx = ident[:ident.find("[")]
        if idx.isdigit(): # if the index part consists of digits
            res_val = idaapi.str2ea(before_idx)
            if res_val != idaapi.BADADDR:
                return (5, (res_val, int(idx)))
            else:
                return False
        else:
            return False


    # match things like:
    #   "bla"
    if len(ident) >= 2 and ident[0] == ident[-1] == '"':
        return (4, ident[1:-1].decode('string_escape')) # Decode hex (and other) escapes

    # match thinfs like:
    #   [0x1337]
    #   [some_global_var]
    if ident[0] == "[" and ident[-1] == "]":
        # Try to parse memory address
        res_val = idaapi.str2ea(ident[1:-1])
        if res_val != idaapi.BADADDR:
            return (0, res_val)
        return False

    # match things like:
    #   arg_4
    #   var_0
    [t, res] = idaapi.get_name_value(idaapi.get_screen_ea(), ident) # TODO: or 64?
    if t == 3:
        # Local variable (arg (pos) or var (neg): sp offset
        res_val = ctypes.c_int32(res).value # TODO: 32 bitness
        #return "[ebp{}{}]".format('+' if res_val >= 0 else '', res_val)
        return (1, res_val)

    # match things like:
    #   eax
    #   ebp
    if idaapi.str2reg(ident) != -1:
        return (2, ident)

    # match things like:
    #   0x1337
    #   some_global_var
    res_val = idaapi.str2ea(ident)
    if res_val != idaapi.BADADDR:
        return (3, res_val)

    # Failed
    return False


def flatten_list(l):
    return [item for sublist in l for item in sublist]

# Is `sublst` a sublist of `lst`?
def contains_sublist(lst, sublst):
    n = len(sublst)
    return any((sublst == lst[i:i+n]) for i in xrange(len(lst)-n+1))


# Helpers for GUI code
def make_hbox(*children):
    hbox = QtWidgets.QHBoxLayout()
    for child in children:
        if issubclass(type(child), QtWidgets.QWidget):
            hbox.addWidget(child)
        elif issubclass(type(child), QtWidgets.QLayout):
            hbox.addLayout(child)
        elif type(child) is str:
            hbox.addWidget(QtWidgets.QLabel(child))
    return hbox

def make_vbox(*children):
    vbox = QtWidgets.QVBoxLayout()
    for child in children:
        if issubclass(type(child), QtWidgets.QWidget):
            vbox.addWidget(child)
        elif issubclass(type(child), QtWidgets.QLayout):
            vbox.addLayout(child)
        elif type(child) is str:
            vbox.addWidget(QtWidgets.QLabel(child))
    return vbox


# convert RGB tuple to ida color value (BGR)
def col_t2ida(col_tuple):
    return (col_tuple[2] << 16) + (col_tuple[1] << 8) + col_tuple[0]


def col_ida2t(col_ida):
    return (col_ida & 0xFF, (col_ida >> 8) & 0xFF, (col_ida >> 16) & 0xFF)


def opr2str(opr):
    # (0, addr) -> a memory address
    # (1, offs) -> an EBP offset      TODO: arch-independent?
    # (2, name) -> a register name
    # (3, val)  -> a constant
    # (5, (arr, idx)) -> atoi of an array with constant index.
    if opr[0] == 0:
        return "[" + hex(opr[1]) + "]"
    if opr[0] == 1:
        return "[bp{}{:x}]".format('+' if opr[1] >= 0 else '', opr[1])
    if opr[0] == 2:
        return opr[1]
    if opr[0] == 3:
        return hex(opr[1])
    elif opr[0] == 4:
        return '"' + opr[1] + '"'
    else:
        return "atoi({}[{}])".format(opr[1][0], opr[1][1])


def warning_msgbox(warning_str):
    def fun(warning_str):
        idc.Warning(warning_str)
    idaapi.execute_sync(partial(fun, warning_str), idaapi.MFF_FAST)


# TODO: not sure if this should always work (race condition? or not with GIL?)
def asklong(defval, prompt):
    res = [None]  # Python 2 way to assign outside of a nested function
    def fun(defval, prompt):
        res[0] = idc.AskLong(defval, prompt)
    idaapi.execute_sync(partial(fun, defval, prompt), idaapi.MFF_FAST)
    return res[0]


# TODO: Put these global functions somewhere in a scope?
def get_func_type(startEA):
    """
    Parse IDA's guessed type decl
    returns: tuple of: (return type, [arg types])
    (this is a giant hack)
     """

    type_str = idc.GuessType(startEA)

    if not type_str:
        # Probably wasn't a function
        print("ERROR: No function type guess")
        return None

    # Parse strings like this:
    # 'int __cdecl(int argc, const char **argv, const char **envp)'
    # 'int __cdecl(int)'

    # Try to make it into a parsable string
    type_str = re.sub(r"(__cdecl|__fastcall|[0-9_])", '', type_str)

    try:
        parser = pycparser.c_parser.CParser()
        res = parser.parse(type_str + ';')  # Need that semicolon of course
        type_ast = res.ext[0].type

        # Return type
        return_type = type_ast.type.type.names[0]

        # Arguments
        arg_types = []
        if type_ast.args:
            for param in type_ast.args.params:
                if type(param.type) is pycparser.c_ast.PtrDecl:
                    # Pointer, return "ptr" for now
                    arg_types.append("ptr")
                else:
                    arg_types.append(param.type.type.names[0])

        return (return_type, arg_types)
    except:
        print("ERROR: Couldn't parse function type guess")
        return None


def get_func_codeblocks(f):
    cbs = [None]
    def fun():
        cbs[0] = list(sark.codeblocks(start=f.startEA, end=f.endEA))
    idaapi.execute_sync(fun, idaapi.MFF_READ)
    return cbs[0]


def get_current_codeblock():
    cb = [None]
    def fun():
        cb[0] = sark.CodeBlock()
    idaapi.execute_sync(fun, idaapi.MFF_READ)
    return cb[0]


def reset_block_colors(f):
    def fun():
        cbs = sark.codeblocks(start=f.startEA, end=f.endEA)
        for cb in cbs:
            cb.color = 0xFFFFFF
    idaapi.execute_sync(fun, idaapi.MFF_WRITE)


def set_block_color(addr, color):
    def fun(addr, color):
        cb = sark.CodeBlock(addr)
        if cb:
            cb.color = color
    idaapi.execute_sync(partial(fun, addr, color), idaapi.MFF_WRITE)


def get_all_blocks_of_color(f, color):
    if type(color) is list:
        colors = color
    else:
        colors = [color]

    res_cbs = []
    cbs = list(sark.codeblocks(start=f.startEA, end=f.endEA))
    for cb in cbs:
        if cb.color in colors:
            res_cbs.append(cb)
    return res_cbs


def get_segment_names(seg):
    names = []
    def fun(seg):
        names.extend([(a, n) for (a, n) in idautils.Names()
                      if seg.startEA <= a < seg.endEA])
    idaapi.execute_sync(partial(fun, seg), idaapi.MFF_READ)
    return names


def patch_bytes(addr, bs):
    def fun(addr, bs):
        idaapi.patch_many_bytes(addr, bs)
    idaapi.execute_ui_requests((partial(fun, addr, bs),))


def set_func_end(func_addr, end_addr):
    def fun(func_addr, end_addr):
        idaapi.func_setend(func_addr, end_addr)
    idaapi.execute_ui_requests((partial(fun, func_addr, end_addr),))


def analyze_area(begin_addr, end_addr):
    def fun(begin_addr, end_addr):
        idaapi.analyze_area(begin_addr, end_addr)
    idaapi.execute_ui_requests((partial(fun, begin_addr, end_addr),))


def set_graph_view():
    def fun():
        idaapi.set_view_renderer_type(
            idaapi.get_current_viewer(), idaapi.TCCRT_GRAPH)
    idaapi.execute_ui_requests((fun,))


def set_flat_view():
    def fun():
        idaapi.set_view_renderer_type(
            idaapi.get_current_viewer(), idaapi.TCCRT_FLAT)
    idaapi.execute_ui_requests((fun,))


def fix_graph_layout():
    def fun():
        idaapi.update_action_state("GraphLayout", 0)
        idaapi.process_ui_action("GraphLayout")
    idaapi.execute_ui_requests((fun,))


def trans_cb_addr_to_IDA(addr):
    try:
        cb = sark.CodeBlock(addr)
        if cb:
            return cb.startEA
        return idaapi.BADADDR
    except:
        return idaapi.BADADDR
