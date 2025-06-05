# Ghidra analyzer script
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor

def decompile(program, function):
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(program)
    options = DecompileOptions()
    decomp_interface.setOptions(options)
    results = decomp_interface.decompileFunction(function, 60, TaskMonitor.DUMMY)
    if results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    return None

program = getCurrentProgram()
listing = program.getListing()
functions = listing.getFunctions(True)
output = ""

for function in functions:
    decompiled = decompile(program, function)
    if decompiled:
        output += "Function: " + function.getName() + "\n"
        output += decompiled + "\n"

print(output)