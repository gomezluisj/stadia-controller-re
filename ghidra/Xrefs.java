import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
public class Xrefs extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        for (String a : args) {
            Address addr = toAddr(Long.parseLong(a.replace("0x",""),16));
            Function f = getFunctionAt(addr);
            println("=== xrefs to " + addr + " (" + (f!=null?f.getName():"?") + ")");
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(addr);
            while (it.hasNext()) {
                Reference r = it.next();
                Function src = getFunctionContaining(r.getFromAddress());
                println(r.getReferenceType() + " from " + r.getFromAddress() + (src!=null?" ("+src.getName()+")":""));
            }
        }
    }
}
