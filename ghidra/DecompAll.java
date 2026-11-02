import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class DecompAll extends GhidraScript {
    public void run() throws Exception {
        String out = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/home/luis/ghidra_work/bruce_decomp.c";
        PrintWriter w = new PrintWriter(new FileWriter(out));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int n=0, fail=0;
        while (it.hasNext()) {
            Function f = it.next();
            w.println("// ==== " + f.getName() + " @ " + f.getEntryPoint() + " ====");
            DecompileResults r = di.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
            else { w.println("// decompile failed"); fail++; }
            n++;
        }
        w.close(); println("done: " + n + " failed: " + fail + " -> " + out);
    }
}
