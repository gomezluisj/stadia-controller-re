import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class Xrefs extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: Xrefs.java <hex_addr> [...]");
            return;
        }
        for (String a : args) {
            long raw = Long.parseLong(a.replaceFirst("^0[xX]", ""), 16);
            Address addr = toAddr(raw);
            Function f = getFunctionAt(addr);
            println("=== xrefs to " + addr + " (" + (f != null ? f.getName() : "?") + ")");
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(addr);
            while (it.hasNext()) {
                Reference r = it.next();
                Function src = getFunctionContaining(r.getFromAddress());
                println(r.getReferenceType() + " from " + r.getFromAddress() + (src != null ? " (" + src.getName() + ")" : ""));
            }
        }
    }
}
