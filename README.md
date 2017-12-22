# Experimental opaque predicate detection for IDA Pro

Drop (**D**rop **R**emoves **O**paque **P**redicates) is **experimental** an IDA Pro plugin capable of detecting several types of opaque predicates in obfuscated binaries by making use of the symbolic-execution engine *angr* and its components.
Specifically, Drop can detect, highlight and (primitively) remove the following types of opaque predicates:

- invariant opaque predicates (i.e. "normal" opaque predicates without context)
- contextual opaque predicates (i.e. opaque predicates that depend on one or more invariants at the predicate location)

In general, the plugin is built to be as interactive as possible, allowing the analyst to specify additional context through function hooking, symbolic global variables and additional (in-)equality constraints.

## Disclaimers

- This code was written during an internship. It is not a Riscure product and Riscure does not support or maintain this code.
- This is experimental code, intended as an experiment to see what can be accomplished by combining `angr` and IDA Pro for this purpose.
    - Because of certain heuristics, the plugin will in various scenarios result in false positives, false negatives, or both.
    - In certain (often complex) functions, SMT constraints will become very large, and solving time might become unreasonably large.
  	  Drop provides a button to kill the current analysis, but because of Z3's architecture, this can occasionally kill IDA itself as well.
      It is therefore recommended you save your database before performing any heavy analysis.

## Third-party dependencies

Because of the instable nature of the APIs provided by angr and its components, Drop requires a very specific version of each to be installed.
In order to make installation easier, some of these have been provided as Python `.egg` files in the `dependencies` folder.
See the *Installation* section below for instructions on how to install these dependencies.

## Installation

This assumes a 64-bit Windows 7 installation with IDA 6.95. Other operating systems are not tested an will require a different installation procedure. Currently, IDA 7.0 and 64-bit Python are not supported. This might change in the future.

It is assumed that (32-bit) Python 2.7, `pip` and `easy_install` are installed, as they come with IDA 6.95.

1. Make sure the 32-bit Python 2.7 executable directories are in your PATH:
    - `;C:\Python27;C:\Python27\Scripts`

2. Run the following commands:
    - `cd path_to_drop/dependencies`
    - `pip install -r requirements.txt`
    - `easy_install -Z archinfo-6.7.1.13-py2.7.egg pyvex-6.7.1.31-py2.7.egg cle-6.7.1.31-py2.7.egg simuvex-6.7.1.31-py2.7.egg capstone-3.0.4-py2.7.egg angr-6.7.1.31-py2.7.egg`
	
3. Copy `drop/` and `drop.py` to `plugins/` in your IDA installation folder.

4. Done!

## Basic usage
The following video shows Drop in action on a simple function containing the opaque predicate `7*x*x-1 != y*y`: https://streamable.com/s7fjw. The source code of the program seen in that video can be found in the demo folder.

In general, the workflow with Drop is is follows:

1. Open a binary\* in IDA Pro.

2. Make sure the cursor is located within a function.

3. Launch Drop with Alt+F6.

4. Follow the steps shown in the panel:

    1. Let angr perform a rudimentary concrete trace through the function by pressing '*concrete trace...*' or manually mark code-blocks to include in the analysis.

    2. Click the '*along trace*' button to start opaque predicate detection on the currently marked basic-blocks.

    3. Optionally (and very experimentally), patch any resulting unreachable code with NOP instructions, to hopefully simplify the function's graph view and decompilation output.

Optionally, one can specify context during step 2 to improve symbolic analysis, this is especially helpful in larger functions with many variables or function calls.

\* only x86 binaries have been properly tested.