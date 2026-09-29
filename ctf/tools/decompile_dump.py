# decompile_dump.py — Ghidra headless post-script (Jython)
# Decompiles every function in the current program and writes the
# pseudocode to the output file passed as the first script argument.
#
# Not meant to be run directly — invoked by Ghidra's analyzeHeadless
# via -postScript, called from reverse.py.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def run():
    args = getScriptArgs()
    if len(args) < 1:
        print("ERROR: no output path passed to decompile_dump.py")
        return
    out_path = args[0]

    program = getCurrentProgram()
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()

    func_manager = program.getFunctionManager()
    functions = list(func_manager.getFunctions(True))

    out_file = open(out_path, "w")
    try:
        out_file.write("// %d function(s) found\n\n" % len(functions))
        for func in functions:
            out_file.write(
                "// ==== Function: %s @ %s ====\n"
                % (func.getName(), func.getEntryPoint())
            )
            try:
                result = decompiler.decompileFunction(func, 60, monitor)
                if result and result.decompileCompleted():
                    decompiled = result.getDecompiledFunction()
                    out_file.write(decompiled.getC())
                else:
                    out_file.write("// [decompile failed or timed out]\n")
            except Exception as e:
                out_file.write("// [error decompiling: %s]\n" % str(e))
            out_file.write("\n\n")
    finally:
        out_file.close()
        decompiler.dispose()


run()
