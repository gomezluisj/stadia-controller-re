ENTRY(Reset_Handler)

MEMORY
{
    DTCM (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

SECTIONS
{
    . = 0x20000000;
    .vectors :
    {
        KEEP(*(.vectors))
        . = 0x400;
    } > DTCM =0x00

    .ivt 0x20000400 :
    {
        KEEP(*(.ivt))
        KEEP(*(.boot_data))
        . = 0x400;
    } > DTCM =0x00

    .text 0x20000800 :
    {
        *(.text*)
        *(.rodata*)
    } > DTCM

    .data :
    {
        *(.data*)
    } > DTCM

    .bss (NOLOAD) :
    {
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        __bss_end__ = .;
    } > DTCM

    _estack = ORIGIN(DTCM) + LENGTH(DTCM) - 16;
}
