CC      := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy
OBJDUMP := arm-none-eabi-objdump
CFLAGS  := -mcpu=cortex-m7 -mthumb -Os -ffreestanding -nostdlib -Wall -Wextra
LDFLAGS := -T link.ld -nostdlib -Wl,--gc-sections

all: build/stadia_hello.bin

build/stadia_hello.elf: main.c link.ld
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) main.c -o $@

build/stadia_hello.bin: build/stadia_hello.elf
	$(OBJCOPY) -O binary $< $@
	@ls -lh $@

disasm: build/stadia_hello.elf
	$(OBJDUMP) -d $<

clean:
	rm -rf build
