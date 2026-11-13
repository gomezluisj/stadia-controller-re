import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DecompAll extends GhidraScript {
    public void run() throws Exception {
        String out = getScriptArgs().length > 0 ? getScriptArgs()[0] : "./ghidra_work/bruce_decomp.c";
        File outFile = new File(out);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        DecompInterface di = new DecompInterface();
        PrintWriter w = null;
        int n = 0, fail = 0;
        try {
            w = new PrintWriter(new FileWriter(outFile));
            if (!di.openProgram(currentProgram)) {
                println("openProgram failed: " + di.getLastMessage());
                return;
            }
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                w.println("// ==== " + f.getName() + " @ " + f.getEntryPoint() + " ====");
                DecompileResults r = di.decompileFunction(f, 60, monitor);
                if (r != null && r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
                else { w.println("// decompile failed"); fail++; }
                n++;
            }
        } finally {
            if (w != null) w.close();
            di.closeProgram();
            di.dispose();
        }
        println("done: " + n + " failed: " + fail + " -> " + outFile.getPath());
    }
}
