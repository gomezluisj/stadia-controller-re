import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompForce extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (String a : args) {
            Address addr = toAddr(Long.parseLong(a.replace("0x",""), 16));
            Function f = getFunctionAt(addr);
            if (f == null) {
                f = createFunction(addr, null);
            }
            if (f == null) { println("NO FUNC CREABLE at " + addr); continue; }
            println("### " + f.getName() + " @ " + f.getEntryPoint());
            DecompileResults r = di.decompileFunction(f, 180, monitor);
            if (r != null && r.decompileCompleted()) println(r.getDecompiledFunction().getC());
            else println("// decompile failed");
        }
    }
}
