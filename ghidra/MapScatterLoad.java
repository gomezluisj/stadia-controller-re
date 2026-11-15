// Map Reset_Handler FlexRAM (ITCM/DTCM) scatter-load sections, MMIO windows,
// and core Stadia firmware labels into an already-loaded slot image.
// Compatible with Ghidra GUI Script Manager and analyzeHeadless -postScript.
//@category Stadia

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.io.ByteArrayInputStream;

public class MapScatterLoad extends GhidraScript {

    private static final int BUILD_INFO_MAGIC = 0x747315A2;
    private static final int BUILD_INFO_FOOTER = 0x4786CD88;
    private static final int STACK_FILL_MAGIC = 0xAABBAABB;
    private static final long[] CANDIDATE_BASES = new long[] { 0x60040000L, 0x60840000L };

    private Address addr(long vma) {
        return toAddr(vma & 0xFFFFFFFFL);
    }

    private long u32(Memory mem, long vma) throws Exception {
        return Integer.toUnsignedLong(mem.getInt(addr(vma)));
    }

    private boolean rangeFree(Memory mem, long start, long size) {
        if (size <= 0) {
            return false;
        }
        Address aStart = addr(start);
        Address aEnd = addr(start + size - 1L);
        return !mem.intersects(aStart, aEnd);
    }

    private void createCopiedBlock(
            Memory mem, String name, long vmaStart, long lmaStart, long size, boolean exec)
            throws Exception {
        if (!rangeFree(mem, vmaStart, size)) {
            println("Skipping existing/overlapping block " + name + " @ 0x" + Long.toHexString(vmaStart));
            return;
        }
        byte[] bytes = new byte[(int) size];
        mem.getBytes(addr(lmaStart), bytes);
        MemoryBlock blk = mem.createInitializedBlock(
            name, addr(vmaStart), new ByteArrayInputStream(bytes), size, monitor, false);
        blk.setRead(true);
        blk.setWrite(true);
        blk.setExecute(exec);
        blk.setComment("Copied from Flash LMA 0x" + Long.toHexString(lmaStart) + " by Reset_Handler");
        println(String.format("Mapped %-16s 0x%08x..0x%08x (<- 0x%08x, %d B)",
            name, vmaStart, vmaStart + size, lmaStart, size));
    }

    private void createZeroBlock(Memory mem, String name, long start, long size, byte fill)
            throws Exception {
        if (!rangeFree(mem, start, size)) {
            println("Skipping existing/overlapping block " + name + " @ 0x" + Long.toHexString(start));
            return;
        }
        MemoryBlock blk = mem.createInitializedBlock(name, addr(start), size, fill, monitor, false);
        blk.setRead(true);
        blk.setWrite(true);
        blk.setExecute(false);
        println(String.format("Mapped %-16s 0x%08x..0x%08x (%d B)", name, start, start + size, size));
    }

    private void createUninitBlock(
            Memory mem, String name, long start, long size, boolean isVolatile) throws Exception {
        if (!rangeFree(mem, start, size)) {
            println("Skipping existing/overlapping block " + name + " @ 0x" + Long.toHexString(start));
            return;
        }
        MemoryBlock blk = mem.createUninitializedBlock(name, addr(start), size, false);
        blk.setRead(true);
        blk.setWrite(true);
        blk.setExecute(false);
        blk.setVolatile(isVolatile);
        println(String.format("Mapped %-16s 0x%08x..0x%08x (%d B)", name, start, start + size, size));
    }

    private void labelIfValid(long vma, String name) throws Exception {
        if (vma != 0 && currentProgram.getMemory().contains(addr(vma))) {
            createLabel(addr(vma), name, false, SourceType.USER_DEFINED);
        }
    }

    private long detectSlotBase(Memory mem) throws Exception {
        for (long base : CANDIDATE_BASES) {
            Address biAddr = addr(base + 0x400L);
            if (mem.contains(biAddr) && mem.contains(addr(base + 0x62CL))) {
                if (mem.getInt(biAddr) == BUILD_INFO_MAGIC
                        && mem.getInt(addr(base + 0x4FCL)) == BUILD_INFO_FOOTER) {
                    return base;
                }
            }
        }
        long imageBase = currentProgram.getImageBase().getOffset();
        if (mem.contains(addr(imageBase + 0x5F4L))) {
            return imageBase;
        }
        return -1L;
    }

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        long slotBase = detectSlotBase(mem);
        if (slotBase < 0) {
            printerr("Could not locate Stadia slot image with BuildInfo/Reset_Handler literal pool.");
            return;
        }

        // Read 15-word Reset_Handler scatter-load literal pool at slotBase + 0x5f4..0x62c
        long[] w = new long[15];
        for (int i = 0; i < 15; i++) {
            w[i] = u32(mem, slotBase + 0x5F4L + (i * 4L));
        }

        if (w[3] != 0x20000000L || w[7] != 0x00000000L || (int) w[13] != STACK_FILL_MAGIC) {
            printerr(String.format(
                "Scatter literal pool at 0x%08x failed sanity check (data2=0x%08x, itcm=0x%08x, fill=0x%08x).",
                slotBase + 0x5F4L, w[3], w[7], w[13]));
            return;
        }

        long dataLma = w[0];
        long dataVmaStart = w[1];
        long dataVmaEnd = w[2];
        long bssLowStart = w[4];
        long bssLowEnd = w[5];
        long itcmLma = w[6];
        long itcmVmaStart = w[7];
        long itcmVmaEnd = w[8];
        long bssHighStart = w[9];
        long bssHighEnd = w[10];
        long stackStart = w[11];
        long stackEnd = w[12];
        long entryAfterInit = w[14] & ~1L;

        int buildNumber = mem.getInt(addr(slotBase + 0x414L));
        println(String.format("Detected slot base 0x%08x (build %d)", slotBase, buildNumber));

        createCopiedBlock(mem, "ITCM_RAMFUNC", itcmVmaStart, itcmLma, itcmVmaEnd - itcmVmaStart, true);
        createZeroBlock(mem, "DTCM_BSS_LOW", bssLowStart, bssLowEnd - bssLowStart, (byte) 0);
        createCopiedBlock(mem, "DTCM_DATA", dataVmaStart, dataLma, dataVmaEnd - dataVmaStart, false);
        createUninitBlock(mem, "DTCM_NOINIT", dataVmaEnd, bssHighStart - dataVmaEnd, false);
        createZeroBlock(mem, "DTCM_BSS_HIGH", bssHighStart, bssHighEnd - bssHighStart, (byte) 0);
        createZeroBlock(mem, "DTCM_STACK", stackStart, stackEnd - stackStart, (byte) 0);
        createUninitBlock(mem, "PERIPHERALS_IMXRT", 0x40000000L, 0x00400000L, true);
        createUninitBlock(mem, "CORTEX_M7_PPB", 0xE0000000L, 0x00100000L, true);

        labelIfValid(slotBase + 0x400L, "BuildInfo_Header");
        labelIfValid(slotBase + 0x500L, "Reset_Handler");
        labelIfValid(entryAfterInit, "cpp_init_and_main");

        long ivtVma = u32(mem, slotBase + 0x1CL);
        labelIfValid(ivtVma, "Trailing_IVT");
        if (mem.contains(addr(ivtVma + 0x18L))) {
            labelIfValid(u32(mem, ivtVma + 0x10L), "Trailing_BootData");
            labelIfValid(u32(mem, ivtVma + 0x18L), "Trailing_CSF");
        }

        // Exact DTCM symbols verified for bruce build 337784
        if (buildNumber == 337784 && slotBase == 0x60040000L) {
            labelIfValid(0x00000FACL, "DCACHE_CleanByRange");
            labelIfValid(0x00001084L, "OCOTP_ReadFuseWord");
            labelIfValid(0x20003670L, "usb_vendor_ctx");
            labelIfValid(0x20003800L, "usb_vendor_build_info");
            labelIfValid(0x20003808L, "usb_vendor_unlock_status");
            labelIfValid(0x20003810L, "usb_vendor_serial");
            labelIfValid(0x20003835L, "usb_vendor_mfg_date");
            labelIfValid(0x20003841L, "usb_vendor_device_color");
            labelIfValid(0x20003848L, "usb_vendor_battery_soc");
            labelIfValid(0x2000384CL, "usb_vendor_prov_state");
            labelIfValid(0x20003D68L, "uxCriticalNesting");
            labelIfValid(0x20003D80L, "_impure_ptr");
            labelIfValid(0x2001EE0CL, "g_VendorUsbTask_shared_ptr");
            labelIfValid(0x600772F4L, "VendorUsb_UpdateGauge");
            labelIfValid(0x60077362L, "VendorUsb_Ep0Dispatch");
            labelIfValid(0x6010A0DCL, "g_ProvisioningStateTable");
            labelIfValid(0x6010A174L, "g_VendorUsbTask_RpcTable");
        }

        // Disassemble ITCM_RAMFUNC so direct calls to 0x0000xxxx resolve cleanly
        MemoryBlock itcmBlk = mem.getBlock("ITCM_RAMFUNC");
        if (itcmBlk != null) {
            disassemble(new AddressSet(itcmBlk.getStart(), itcmBlk.getEnd()));
        }
        println("MapScatterLoad completed.");
    }
}
