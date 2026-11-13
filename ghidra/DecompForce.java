import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import java.math.BigInteger;

public class DecompForce extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: DecompForce.java <hex_addr> [...]");
            return;
        }
        Register tmode = currentProgram.getProgramContext().getRegister("TMode");
        DecompInterface di = new DecompInterface();
        try {
            if (!di.openProgram(currentProgram)) {
                println("openProgram failed: " + di.getLastMessage());
                return;
            }
            for (String a : args) {
                long raw = Long.parseLong(a.replaceFirst("^0[xX]", ""), 16);
                Address addr = toAddr(raw & ~1L);
                if (getInstructionAt(addr) == null) {
                    if (tmode != null) {
                        try {
                            currentProgram.getProgramContext().setValue(tmode, addr, addr, BigInteger.ONE);
                        } catch (ContextChangeException ignored) {
                            // Keep existing context if units overlap.
                        }
                    }
                    disassemble(addr);
                }
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
        } finally {
            di.closeProgram();
            di.dispose();
        }
    }
}
