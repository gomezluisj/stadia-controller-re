#include <stddef.h>
#include <stdint.h>
#include "bcm43458f_hcd.h"
#include "bt_hid.h"
#include "usb_cdc.h"

#ifndef STADIA_DEBUG_CONSOLE
#define STADIA_DEBUG_CONSOLE 1
#endif

extern uint32_t _estack;
extern uint32_t __bss_start__;
extern uint32_t __bss_end__;

__attribute__((used))
void *memset(void *dst, int c, size_t n) {
    uint8_t *p = (uint8_t *)dst;
    while (n--) {
        *p++ = (uint8_t)c;
    }
    return dst;
}

void Reset_Handler(void);
static void Default_Handler(void) { while (1) {} }

/* Cortex-M7 vector table @ 0x20000000 */
__attribute__((section(".vectors"), used))
const uint32_t vectors[] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler, /* NMI */
    (uint32_t)Default_Handler, /* HardFault */
    (uint32_t)Default_Handler, /* MemManage */
    (uint32_t)Default_Handler, /* BusFault */
    (uint32_t)Default_Handler, /* UsageFault */
};

typedef struct __attribute__((packed)) {
    uint32_t header;    /* 0x412000D1: tag=0xD1, len=0x0020 (BE), ver=0x41 */
    uint32_t entry;
    uint32_t reserved1;
    uint32_t dcd;
    uint32_t boot_data;
    uint32_t self;
    uint32_t csf;
    uint32_t reserved2;
} hab_ivt_t;

typedef struct __attribute__((packed)) {
    uint32_t start;
    uint32_t length;
    uint32_t plugin;
} hab_boot_data_t;

__attribute__((section(".ivt"), used))
const hab_ivt_t ivt = {
    .header    = 0x412000D1u,
    .entry     = 0x20000000u, /* vector table base */
    .reserved1 = 0u,
    .dcd       = 0u,
    .boot_data = 0x20000420u,
    .self      = 0x20000400u,
    .csf       = 0u,
    .reserved2 = 0u,
};

__attribute__((section(".boot_data"), used))
const hab_boot_data_t boot_data = {
    .start  = 0x20000000u,
    .length = 0x00018000u,
    .plugin = 0u,
};

/* Diagnostic status block placed at fixed DTCM address 0x2001C000 */
typedef struct {
    volatile uint32_t magic;            /* 0x53544144 = "STAD" */
    volatile uint32_t version;          /* 3 */
    volatile uint32_t digprog;          /* USB_ANALOG_DIGPROG (0x400D8260) */
    volatile uint32_t ocotp_cfg5;       /* OCOTP->CFG5 (0x401F4460) */
    volatile uint32_t ticks;            /* Heartbeat counter */
    volatile uint32_t gpio_psr[4];      /* Live GPIO1..4 PSR snapshots */
    volatile uint32_t bt_hci_ok;        /* 1 if BCM43458F returned HCI_Reset CC (04 0E) */
    volatile uint32_t bt_hci_rx_len;    /* Bytes received on LPUART3 after HCI_Reset */
    volatile uint32_t bt_hci_rx0;       /* First 4 RX bytes (LE) */
    volatile uint32_t bt_hci_rx1;       /* Next 4 RX bytes (LE) */
    volatile uint32_t bt_uart_baud_reg; /* LPUART3_BAUD programmed value */
} diag_status_t;

#define DIAG_STATUS ((diag_status_t *)0x2001C000u)

#define REG32(addr) (*(volatile uint32_t *)(addr))
#define REG16(addr) (*(volatile uint16_t *)(addr))

/* Watchdogs */
#define WDOG1_WCR    REG16(0x400B8000u)
#define WDOG2_WCR    REG16(0x400D0000u)
#define RTWDOG_CS    REG32(0x400BC000u)
#define RTWDOG_CNT   REG32(0x400BC004u)
#define RTWDOG_TOVAL REG32(0x400BC008u)

/* CCM clock gating & dividers */
#define CCM_CSCDR1  REG32(0x400FC024u)
#define CCM_CCGR0   REG32(0x400FC068u)
#define CCM_CCGR1   REG32(0x400FC06Cu)
#define CCM_CCGR2   REG32(0x400FC070u)
#define CCM_CCGR3   REG32(0x400FC074u)
#define CCM_CCGR4   REG32(0x400FC078u)
#define CCM_CCGR5   REG32(0x400FC07Cu)
#define CCM_CCGR6   REG32(0x400FC080u)

/* IOMUXC_GPR GPIO1..4 vs fast GPIO6..9 routing */
#define IOMUXC_GPR_GPR(idx) REG32(0x400AC068u + ((idx) * 4u))

/* GPIO1..4 bases and register accessors */
#define GPIO1_BASE 0x401B8000u
#define GPIO2_BASE 0x401BC000u
#define GPIO3_BASE 0x401C0000u
#define GPIO4_BASE 0x401C4000u

#define GPIO_DR(b)   REG32((b) + 0x00u)
#define GPIO_GDIR(b) REG32((b) + 0x04u)
#define GPIO_PSR(b)  REG32((b) + 0x08u)

/* LPUART3 for BCM43458F Bluetooth HCI */
#define LPUART3_BASE   0x4018C000u
#define LPUART_GLOBAL(b) REG32((b) + 0x08u)
#define LPUART_BAUD(b)   REG32((b) + 0x10u)
#define LPUART_STAT(b)   REG32((b) + 0x14u)
#define LPUART_CTRL(b)   REG32((b) + 0x18u)
#define LPUART_DATA(b)   REG32((b) + 0x1Cu)
#define LPUART_MODIR(b)  REG32((b) + 0x24u)
#define LPUART_FIFO(b)   REG32((b) + 0x28u)

/* ADC1/ADC2 for analog sticks and triggers */
#define ADC1_BASE  0x400C4000u
#define ADC2_BASE  0x400C8000u
#define ADC_HC0(b) REG32((b) + 0x00u)
#define ADC_HS(b)  REG32((b) + 0x20u)
#define ADC_R0(b)  REG32((b) + 0x24u)
#define ADC_CFG(b) REG32((b) + 0x44u)
#define ADC_GC(b)  REG32((b) + 0x48u)
#define ADC_GS(b)  REG32((b) + 0x4Cu)

/* LPI2C register offsets */
#define LPI2C_MCR(b)    REG32((b) + 0x10u)
#define LPI2C_MSR(b)    REG32((b) + 0x14u)
#define LPI2C_MCFGR1(b) REG32((b) + 0x24u)
#define LPI2C_MCCR0(b)  REG32((b) + 0x48u)
#define LPI2C_MFCR(b)   REG32((b) + 0x58u)
#define LPI2C_MTDR(b)   REG32((b) + 0x60u)
#define LPI2C_MRDR(b)   REG32((b) + 0x70u)

#define LPI2C1_BASE 0x403F0000u
#define LPI2C2_BASE 0x403F4000u
#define LPI2C3_BASE 0x403F8000u
#define LPI2C4_BASE 0x403FC000u

/* FlexPWM4 for Left (SM2 Ch A / GPIO_B1_14) & Right (SM3 Ch A / GPIO_B1_15) haptics
 * and XBARA1 (0x403BC000) to tie active-LOW FLEXPWM4_FAULT0..3 to LOGIC_HIGH.
 * PRSC=6 (/64) @ 132 MHz IPG_CLK -> 2.0625 MHz; VAL1=69 -> ~29.9 kHz (matches stock). */
#define PWM4_BASE        0x403E8000u
#define XBARA1_BASE      0x403BC000u
#define PWM4_PERIOD_VAL1 69u

static void delay_cycles(volatile uint32_t n) {
    while (n--) {
        __asm__ volatile ("nop");
    }
}

static void lpi2c_init(uint32_t base) {
    LPI2C_MCR(base) = (1u << 1); /* RST */
    delay_cycles(1000u);
    LPI2C_MCR(base) = 0u;
    LPI2C_MCFGR1(base) = 1u; /* PRESCALE=/2 -> ~50-300 kHz across 10-60 MHz root */
    LPI2C_MCCR0(base) = (0x0Au << 24) | (0x14u << 16) | (0x28u << 8) | 0x38u;
    LPI2C_MFCR(base) = 0u;
    LPI2C_MCR(base) = 1u; /* MEN */
}

static int lpi2c_wait_tx(uint32_t base) {
    for (uint32_t i = 0; i < 100000u; ++i) {
        uint32_t msr = LPI2C_MSR(base);
        if (msr & (1u << 10)) { /* NDF */
            return -1;
        }
        if (msr & (1u << 0)) { /* TDF */
            return 0;
        }
    }
    return -1;
}

static int lpi2c_write_reg(uint32_t base, uint8_t addr7, uint8_t reg, uint8_t val) {
    LPI2C_MSR(base) = 0x7F00u; /* clear status flags */
    if (lpi2c_wait_tx(base) < 0) return -1;
    LPI2C_MTDR(base) = 0x400u | ((uint32_t)addr7 << 1); /* START + W */
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = reg;
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = val;
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = 0x200u; /* STOP */
    for (uint32_t i = 0; i < 100000u; ++i) {
        uint32_t msr = LPI2C_MSR(base);
        if (msr & (1u << 10)) return -1;
        if (msr & (1u << 9)) return 0; /* SDF */
    }
    return -1;
stop_err:
    LPI2C_MTDR(base) = 0x200u;
    delay_cycles(5000u);
    return -1;
}

static void lpi2c_recover(uint32_t base) {
    LPI2C_MCR(base) |= (1u << 8) | (1u << 9); /* RTF | RRF */
    LPI2C_MSR(base) = 0x7F00u;
}

static int lpi2c_wait_stop(uint32_t base) {
    for (uint32_t i = 0; i < 100000u; ++i) {
        uint32_t msr = LPI2C_MSR(base);
        if (msr & (1u << 10)) { /* NDF */
            lpi2c_recover(base);
            return -1;
        }
        if (msr & (1u << 9)) { /* SDF */
            return 0;
        }
    }
    lpi2c_recover(base);
    return -1;
}

static int lpi2c_read_reg(uint32_t base, uint8_t addr7, uint8_t reg, uint8_t *out) {
    lpi2c_recover(base);
    if (lpi2c_wait_tx(base) < 0) return -1;
    LPI2C_MTDR(base) = 0x400u | ((uint32_t)addr7 << 1);
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = reg;
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = 0x400u | ((uint32_t)addr7 << 1) | 1u;
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = 0x100u; /* RX 1 byte */
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = 0x200u; /* STOP */
    for (uint32_t i = 0; i < 100000u; ++i) {
        uint32_t msr = LPI2C_MSR(base);
        if (msr & (1u << 10)) goto stop_err;
        uint32_t mrdr = LPI2C_MRDR(base);
        if ((mrdr & (1u << 14)) == 0u) {
            *out = (uint8_t)(mrdr & 0xFFu);
            (void)lpi2c_wait_stop(base);
            return 0;
        }
    }
stop_err:
    LPI2C_MTDR(base) = 0x200u;
    delay_cycles(5000u);
    lpi2c_recover(base);
    return -1;
}

static int lpi2c_read_u16_le(uint32_t base, uint8_t addr7, uint8_t reg, uint16_t *out) {
    lpi2c_recover(base);
    if (lpi2c_wait_tx(base) < 0) return -1;
    LPI2C_MTDR(base) = 0x400u | ((uint32_t)addr7 << 1);
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = reg;
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = 0x400u | ((uint32_t)addr7 << 1) | 1u;
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = 0x101u; /* RX 2 bytes */
    if (lpi2c_wait_tx(base) < 0) goto stop_err;
    LPI2C_MTDR(base) = 0x200u; /* STOP */
    uint8_t b[2] = { 0u, 0u };
    for (uint32_t idx = 0u; idx < 2u; ++idx) {
        int got = 0;
        for (uint32_t i = 0u; i < 100000u; ++i) {
            uint32_t msr = LPI2C_MSR(base);
            if (msr & (1u << 10)) goto stop_err;
            uint32_t mrdr = LPI2C_MRDR(base);
            if ((mrdr & (1u << 14)) == 0u) {
                b[idx] = (uint8_t)(mrdr & 0xFFu);
                got = 1;
                break;
            }
        }
        if (!got) goto stop_err;
    }
    (void)lpi2c_wait_stop(base);
    *out = (uint16_t)b[0] | ((uint16_t)b[1] << 8);
    return 0;
stop_err:
    LPI2C_MTDR(base) = 0x200u;
    delay_cycles(5000u);
    lpi2c_recover(base);
    return -1;
}

typedef struct {
    uint32_t base;
    uint32_t mux_scl;
    uint32_t mux_sda;
    uint32_t mux_val;
    uint32_t pad_scl;
    uint32_t pad_sda;
    uint32_t sel_scl;
    uint32_t sel_sda;
    uint32_t sel_val;
} lpi2c_pins_t;

static const lpi2c_pins_t k_i2c_candidates[] = {
    /* LPI2C1: GPIO_AD_B1_00 (SCL) / GPIO_AD_B1_01 (SDA) */
    { LPI2C1_BASE, 0x401F80FCu, 0x401F8100u, 0x13u, 0x401F82ECu, 0x401F82F0u, 0x401F84CCu, 0x401F84D0u, 1u },
    /* LPI2C2: GPIO_B0_04 (SCL) / GPIO_B0_05 (SDA) */
    { LPI2C2_BASE, 0x401F814Cu, 0x401F8150u, 0x12u, 0x401F833Cu, 0x401F8340u, 0x401F84D4u, 0x401F84D8u, 1u },
    /* LPI2C3: GPIO_AD_B1_07 (SCL) / GPIO_AD_B1_06 (SDA) */
    { LPI2C3_BASE, 0x401F8118u, 0x401F8114u, 0x11u, 0x401F8308u, 0x401F8304u, 0x401F84DCu, 0x401F84E0u, 1u },
    /* LPI2C4: GPIO_AD_B0_12 (SCL) / GPIO_AD_B0_13 (SDA) */
    { LPI2C4_BASE, 0x401F80ECu, 0x401F80F0u, 0x10u, 0x401F82DCu, 0x401F82E0u, 0x401F84E4u, 0x401F84E8u, 1u },
};

static void i2c_ensure_bus(uint32_t idx) {
    const lpi2c_pins_t *p = &k_i2c_candidates[idx];
    REG32(p->mux_scl) = p->mux_val;
    REG32(p->mux_sda) = p->mux_val;
    REG32(p->pad_scl) = 0xD8B0u;
    REG32(p->pad_sda) = 0xD8B0u;
    REG32(p->sel_scl) = p->sel_val;
    REG32(p->sel_sda) = p->sel_val;
    lpi2c_init(p->base);
}

static int probe_lp5562(uint32_t *out_base, uint8_t *out_addr) {
    for (uint32_t c = 0; c < sizeof(k_i2c_candidates) / sizeof(k_i2c_candidates[0]); ++c) {
        const lpi2c_pins_t *p = &k_i2c_candidates[c];
        REG32(p->mux_scl) = p->mux_val;
        REG32(p->mux_sda) = p->mux_val;
        REG32(p->pad_scl) = 0xD8B0u;
        REG32(p->pad_sda) = 0xD8B0u;
        REG32(p->sel_scl) = p->sel_val;
        REG32(p->sel_sda) = p->sel_val;
        lpi2c_init(p->base);
        for (uint8_t addr = 0x30u; addr <= 0x33u; ++addr) {
            if (lpi2c_write_reg(p->base, addr, 0x0Du, 0xFFu) == 0) {
                delay_cycles(50000u);
                lpi2c_write_reg(p->base, addr, 0x00u, 0x40u); /* ChipEnable */
                lpi2c_write_reg(p->base, addr, 0x08u, 0x01u); /* InternalClock */
                lpi2c_write_reg(p->base, addr, 0x70u, 0x00u); /* LED_MAP direct PWM */
                lpi2c_write_reg(p->base, addr, 0x05u, 0xFFu); /* B_CURRENT */
                lpi2c_write_reg(p->base, addr, 0x06u, 0xFFu); /* G_CURRENT */
                lpi2c_write_reg(p->base, addr, 0x07u, 0xFFu); /* R_CURRENT */
                lpi2c_write_reg(p->base, addr, 0x0Fu, 0xFFu); /* W_CURRENT */
                *out_base = p->base;
                *out_addr = addr;
                return 0;
            }
        }
    }
    return -1;
}

static const uint32_t k_gpio_bases[4] = {
    GPIO1_BASE, GPIO2_BASE, GPIO3_BASE, GPIO4_BASE,
};

typedef struct {
    uint32_t mux_reg;
    uint32_t pad_reg;
    uint8_t port_idx; /* 0=GPIO1 .. 3=GPIO4 */
    uint8_t pin;
} gpio_pin_cfg_t;

#define BTN_MASK_GPIO1 ((1u << 0) | (1u << 2)) /* L3, R3 */
#define BTN_MASK_GPIO2 0x0000F80Fu             /* A,B,X,Y (0..3) + Stadia,Options,Menu,Assistant,Capture (11..15) */
#define BTN_MASK_GPIO3 0x0000000Fu             /* D-Pad Up, Down, Left, Right (0..3) */
#define BTN_MASK_GPIO4 0x00000003u             /* L1, R1 (0..1) */

/* 17 button GPIOs from slot_a_bruce.bin pinmux table (idx 0..16 @ 0x60102920)
 * cross-checked with 0x60070744..0x60070a56 HID parsers */
static const gpio_pin_cfg_t k_button_pins[] = {
    { 0x401F81D4u, 0x401F83C4u, 2u, 0u  }, /* idx 0:  GPIO_SD_B1_00 / GPIO3_00 (D-Pad Up) */
    { 0x401F81D8u, 0x401F83C8u, 2u, 1u  }, /* idx 1:  GPIO_SD_B1_01 / GPIO3_01 (D-Pad Down) */
    { 0x401F81DCu, 0x401F83CCu, 2u, 2u  }, /* idx 2:  GPIO_SD_B1_02 / GPIO3_02 (D-Pad Left) */
    { 0x401F81E0u, 0x401F83D0u, 2u, 3u  }, /* idx 3:  GPIO_SD_B1_03 / GPIO3_03 (D-Pad Right) */
    { 0x401F813Cu, 0x401F832Cu, 1u, 0u  }, /* idx 4:  GPIO_B0_00    / GPIO2_00 (A) */
    { 0x401F8140u, 0x401F8330u, 1u, 1u  }, /* idx 5:  GPIO_B0_01    / GPIO2_01 (B) */
    { 0x401F8144u, 0x401F8334u, 1u, 2u  }, /* idx 6:  GPIO_B0_02    / GPIO2_02 (X) */
    { 0x401F8148u, 0x401F8338u, 1u, 3u  }, /* idx 7:  GPIO_B0_03    / GPIO2_03 (Y) */
    { 0x401F8168u, 0x401F8358u, 1u, 11u }, /* idx 8:  GPIO_B0_11    / GPIO2_11 (Stadia) */
    { 0x401F816Cu, 0x401F835Cu, 1u, 12u }, /* idx 9:  GPIO_B0_12    / GPIO2_12 (Options) */
    { 0x401F8170u, 0x401F8360u, 1u, 13u }, /* idx 10: GPIO_B0_13    / GPIO2_13 (Menu) */
    { 0x401F8174u, 0x401F8364u, 1u, 14u }, /* idx 11: GPIO_B0_14    / GPIO2_14 (Assistant) */
    { 0x401F8178u, 0x401F8368u, 1u, 15u }, /* idx 12: GPIO_B0_15    / GPIO2_15 (Capture) */
    { 0x401F80BCu, 0x401F82ACu, 0u, 0u  }, /* idx 13: GPIO_AD_B0_00 / GPIO1_00 (L3) */
    { 0x401F80C4u, 0x401F82B4u, 0u, 2u  }, /* idx 14: GPIO_AD_B0_02 / GPIO1_02 (R3) */
    { 0x401F8014u, 0x401F8204u, 3u, 0u  }, /* idx 15: GPIO_EMC_00   / GPIO4_00 (L1) */
    { 0x401F8018u, 0x401F8208u, 3u, 1u  }, /* idx 16: GPIO_EMC_01   / GPIO4_01 (R1) */
};

static void configure_button_gpios(uint32_t idle_psr[4]) {
    for (uint32_t i = 0; i < sizeof(k_button_pins) / sizeof(k_button_pins[0]); ++i) {
        const gpio_pin_cfg_t *p = &k_button_pins[i];
        uint32_t mask = 1u << p->pin;
        REG32(p->mux_reg) = 5u;      /* ALT5: GPIO */
        REG32(p->pad_reg) = 0xF0B0u; /* Pull-up enabled input */
        IOMUXC_GPR_GPR(p->port_idx) &= ~mask;
        GPIO_GDIR(k_gpio_bases[p->port_idx]) &= ~mask;
    }
    /* Allow RC-filtered button lines to charge before sampling idle high state */
    delay_cycles(2000000u);
    for (uint32_t g = 0; g < 4u; ++g) {
        idle_psr[g] = GPIO_PSR(k_gpio_bases[g]);
    }
}


static uint16_t adc_read_ch(uint32_t base, uint8_t ch) {
    ADC_HC0(base) = (uint32_t)(ch & 0x1Fu);
    for (uint32_t i = 0u; i < 100000u; ++i) {
        if (ADC_HS(base) & 1u) {
            return (uint16_t)(ADC_R0(base) & 0x0FFFu);
        }
    }
    return 0u;
}

static uint16_t adc_read_avg(uint32_t base, uint8_t ch) {
    (void)adc_read_ch(base, ch); /* Discard first conversion after mux switch */
    uint32_t sum = 0u;
    for (uint32_t s = 0u; s < 8u; ++s) {
        sum += adc_read_ch(base, ch);
    }
    return (uint16_t)(sum >> 3);
}

static void adc_cal_unit(uint32_t base) {
    ADC_CFG(base) = 0x0358u; /* 12-bit, IPG/4, long sample time */
    ADC_GS(base) = 2u;       /* Clear CALF */
    ADC_GC(base) = (1u << 7); /* CAL */
    for (uint32_t i = 0u; i < 100000u; ++i) {
        if ((ADC_GC(base) & (1u << 7)) == 0u) {
            break;
        }
    }
    (void)ADC_R0(base);
    ADC_GC(base) = 0u;
}

static const uint8_t k_stick_channels[6] = {
    9u,  /* ADC1_IN9  (GPIO_AD_B1_04): RX */
    10u, /* ADC1_IN10 (GPIO_AD_B1_05): RY */
    11u, /* ADC1_IN11 (GPIO_AD_B1_06): LX */
    12u, /* ADC1_IN12 (GPIO_AD_B1_07): LY */
    8u,  /* ADC1_IN8  (GPIO_AD_B1_03): R2 */
    13u, /* ADC1_IN13 (GPIO_AD_B1_08): L2 */
};

static void adc1_init_sticks(uint16_t idle_sticks[6]) {
    /* Enable L2/R2 Hall sensors via active-LOW GPIO2_10 (GPIO_B0_10) */
    IOMUXC_GPR_GPR(1) &= ~(1u << 10);
    REG32(0x401F8164u) = 5u;
    GPIO_DR(GPIO2_BASE) &= ~(1u << 10);
    GPIO_GDIR(GPIO2_BASE) |= (1u << 10);

    /* Configure GPIO_AD_B1_03..08 (GPIO1_19..24) as hi-Z analog inputs */
    IOMUXC_GPR_GPR(0) &= ~(0x3Fu << 19);
    GPIO_GDIR(GPIO1_BASE) &= ~(0x3Fu << 19);
    for (uint32_t i = 0u; i < 6u; ++i) {
        REG32(0x401F8108u + (i * 4u)) = 5u;
        REG32(0x401F82F8u + (i * 4u)) = 0x0000u;
    }
    delay_cycles(5000000u);

    adc_cal_unit(ADC1_BASE);

    for (uint32_t i = 0u; i < 6u; ++i) {
        (void)adc_read_avg(ADC1_BASE, k_stick_channels[i]);
        idle_sticks[i] = adc_read_avg(ADC1_BASE, k_stick_channels[i]);
    }
    /* Guard against booting with L2/R2 held down (normal idle ~1730-1750) */
    if (idle_sticks[4] < 1500u) idle_sticks[4] = 1745u;
    if (idle_sticks[5] < 1500u) idle_sticks[5] = 1735u;
}

/* Haptics: FlexPWM4 SM2 Ch A (GPIO_B1_14) + GPIO2_16 (Left),
 *          FlexPWM4 SM3 Ch A (GPIO_B1_15) + GPIO2_17 (Right).
 * GPIO2_16 / GPIO2_17 are active-LOW motor driver enables (0=ON, 1=OFF). */
static uint8_t g_rumble_l = 0u;
static uint8_t g_rumble_r = 0u;
static uint32_t g_rumble_wdog = 0u;

static void haptics_gpio_safe_off(void) {
    /* Force active-LOW enables HIGH (disabled) BEFORE enabling output drivers */
    IOMUXC_GPR_GPR(1) &= ~((1u << 16) | (1u << 17));
    REG32(0x401F817Cu) = 5u;      /* GPIO_B1_00 -> GPIO2_16 (Left EN) */
    REG32(0x401F836Cu) = 0x10B0u;
    REG32(0x401F8180u) = 5u;      /* GPIO_B1_01 -> GPIO2_17 (Right EN) */
    REG32(0x401F8370u) = 0x10B0u;
    GPIO_DR(GPIO2_BASE) |= (1u << 16) | (1u << 17);
    GPIO_GDIR(GPIO2_BASE) |= (1u << 16) | (1u << 17);
    g_rumble_l = 0u;
    g_rumble_r = 0u;
    g_rumble_wdog = 0u;
}

static void xbara1_set_conn(uint16_t out_sig, uint8_t in_sig) {
    uint32_t reg_off = (uint32_t)(out_sig & 0xFEu);
    uint32_t shift = (out_sig & 1u) ? 8u : 0u;
    uint16_t v = REG16(XBARA1_BASE + reg_off);
    v = (uint16_t)((v & (uint16_t)~(0xFFu << shift)) | (uint16_t)((uint16_t)in_sig << shift));
    REG16(XBARA1_BASE + reg_off) = v;
}

static void haptics_pwm_init(void) {
    /* Enable XBARA1 clock and route active-LOW FLEXPWM4_FAULT0..3 to LOGIC_HIGH (0x01),
     * matching stock slot_a_bruce.bin @ 0x600d4a6c. */
    CCM_CCGR2 |= (3u << 22);
    __asm__ volatile ("dsb sy");
    xbara1_set_conn(0x13Fu, 0x01u); /* FLEXPWM4_FAULT0 -> LOGIC_HIGH */
    xbara1_set_conn(0x140u, 0x01u); /* FLEXPWM4_FAULT1 -> LOGIC_HIGH */
    xbara1_set_conn(0x125u, 0x01u); /* FLEXPWM1..4_FAULT2 -> LOGIC_HIGH */
    xbara1_set_conn(0x126u, 0x01u); /* FLEXPWM1..4_FAULT3 -> LOGIC_HIGH */

    /* Mux FlexPWM4_PWMA02 (GPIO_B1_14) and FlexPWM4_PWMA03 (GPIO_B1_15) */
    REG32(0x401F81B4u) = 1u;      /* ALT1: FLEXPWM4_PWMA02 */
    REG32(0x401F849Cu) = 1u;      /* FLEXPWM4_PWMA2_SELECT_INPUT */
    REG32(0x401F83A4u) = 0x10B0u;
    REG32(0x401F81B8u) = 1u;      /* ALT1: FLEXPWM4_PWMA03 */
    REG32(0x401F84A0u) = 1u;      /* FLEXPWM4_PWMA3_SELECT_INPUT */
    REG32(0x401F83A8u) = 0x10B0u;

    /* Configure FlexPWM4 SM2 and SM3 matching stock PWM_Init + PWM_SetupPwm
     * (slot_a_bruce.bin @ 0x60053d08, 0x600cf510, 0x600d4b78).
     * Never touch DISMAP1 (+0x2E) — reserved on MIMXRT1061 (causes BusFault). */
    REG16(PWM4_BASE + 0x188u) &= (uint16_t)~((1u << 10) | (1u << 11)); /* Stop RUN */
    REG16(PWM4_BASE + 0x18Eu) |= 0x000Fu; /* FSTS0: clear latched fault flags */
    REG16(PWM4_BASE + 0x190u) = 0x0000u;  /* FFILT0 */
    REG16(PWM4_BASE + 0x182u) = 0x0000u;  /* MASK: unmasked */
    for (uint32_t sm = 2u; sm <= 3u; ++sm) {
        uint32_t sb = PWM4_BASE + (sm * 0x60u);
        REG16(sb + 0x2Cu) = 0x0000u;                              /* DISMAP0: disable fault gating */
        REG16(sb + 0x04u) = (1u << 13);                           /* CTRL2: INDEP=1 */
        REG16(sb + 0x06u) = (1u << 10) | (6u << 4) | (1u << 2);   /* CTRL: FULL=1, PRSC=6 (/64), LDMOD=1 */
        REG16(sb + 0x04u) |= (1u << 6);                           /* CTRL2: FORCE */
        REG16(sb + 0x02u) = 0x0000u;                              /* INIT */
        REG16(sb + 0x0Au) = (uint16_t)(PWM4_PERIOD_VAL1 / 2u);    /* VAL0 */
        REG16(sb + 0x0Eu) = PWM4_PERIOD_VAL1;                     /* VAL1 */
        REG16(sb + 0x12u) = 0x0000u;                              /* VAL2 (PWMA on) */
        REG16(sb + 0x16u) = 0x0000u;                              /* VAL3 (PWMA off = 0%) */
        REG16(sb + 0x30u) = 0x0000u;                              /* DTCNT0 */
        REG16(sb + 0x22u) = 0x0000u;                              /* OCTRL: active-HIGH */
        REG16(PWM4_BASE + 0x180u) |= (uint16_t)(1u << (8u + sm)); /* OUTEN: SM2/SM3 PWMA */
    }
    /* Immediate load (LDMOD=1) of INIT/VAL0/VAL1/VAL2/VAL3 into active registers */
    REG16(PWM4_BASE + 0x188u) |= (uint16_t)((1u << 2) | (1u << 3));
    for (uint32_t i = 0u; i < 1000u; ++i) {
        if ((REG16(PWM4_BASE + 0x188u) & ((1u << 2) | (1u << 3))) == 0u) {
            break;
        }
    }
    REG16(PWM4_BASE + 0x18Eu) |= 0x000Fu;
}

#if STADIA_DEBUG_CONSOLE
static void haptics_print_regs(const char *tag) {
    uint16_t fsts = REG16(PWM4_BASE + 0x18Eu);
    uint16_t outen = REG16(PWM4_BASE + 0x180u);
    uint16_t mctrl = REG16(PWM4_BASE + 0x188u);
    uint16_t c2 = REG16(PWM4_BASE + 0xC0u + 0x04u);
    uint16_t c = REG16(PWM4_BASE + 0xC0u + 0x06u);
    uint16_t v1 = REG16(PWM4_BASE + 0xC0u + 0x0Eu);
    uint16_t v3 = REG16(PWM4_BASE + 0xC0u + 0x16u);
    uint16_t cnt2 = REG16(PWM4_BASE + 0xC0u + 0x00u);
    uint16_t dis2 = REG16(PWM4_BASE + 0xC0u + 0x2Cu);
    usb_cdc_puts(tag);
    usb_cdc_puts(" FSTS="); usb_cdc_put_hex8((uint8_t)(fsts >> 8)); usb_cdc_put_hex8((uint8_t)fsts);
    usb_cdc_puts(" OUT="); usb_cdc_put_hex8((uint8_t)(outen >> 8)); usb_cdc_put_hex8((uint8_t)outen);
    usb_cdc_puts(" MC="); usb_cdc_put_hex8((uint8_t)(mctrl >> 8)); usb_cdc_put_hex8((uint8_t)mctrl);
    usb_cdc_puts(" C2="); usb_cdc_put_hex8((uint8_t)(c2 >> 8)); usb_cdc_put_hex8((uint8_t)c2);
    usb_cdc_puts(" C="); usb_cdc_put_hex8((uint8_t)(c >> 8)); usb_cdc_put_hex8((uint8_t)c);
    usb_cdc_puts(" D2="); usb_cdc_put_hex8((uint8_t)(dis2 >> 8)); usb_cdc_put_hex8((uint8_t)dis2);
    usb_cdc_puts(" V1="); usb_cdc_put_u32(v1);
    usb_cdc_puts(" V3="); usb_cdc_put_u32(v3);
    usb_cdc_puts(" CNT="); usb_cdc_put_u32(cnt2);
    usb_cdc_puts("\r\n");
    usb_cdc_poll();
}
#endif

static void haptics_set_motor(int is_right, uint8_t pct) {
    uint32_t sm = is_right ? 3u : 2u;
    uint32_t en_bit = 1u << (is_right ? 17u : 16u);
    uint32_t sb = PWM4_BASE + (sm * 0x60u);
    if (pct == 0u) {
        REG16(sb + 0x12u) = 0u;
        REG16(sb + 0x16u) = 0u;
        REG16(PWM4_BASE + 0x188u) |= (uint16_t)(1u << sm);              /* LDOK */
        GPIO_DR(GPIO2_BASE) |= en_bit;                                  /* Active-LOW OFF */
        REG16(PWM4_BASE + 0x188u) &= (uint16_t)~(1u << (8u + sm));      /* Stop RUN */
    } else {
        if (pct > 100u) pct = 100u;
        /* Map non-zero intensity 1..100% -> 25..95% ERM duty so motor overcomes stiction */
        uint32_t duty = 25u + (((uint32_t)pct * 70u) / 100u);
        if (duty > 95u) duty = 95u;
        uint16_t val3 = (uint16_t)((duty * (uint32_t)PWM4_PERIOD_VAL1) / 100u);
        if (val3 == 0u) val3 = 1u;
        if (val3 >= PWM4_PERIOD_VAL1) val3 = (uint16_t)(PWM4_PERIOD_VAL1 - 1u);
        REG16(sb + 0x0Eu) = PWM4_PERIOD_VAL1;
        REG16(sb + 0x12u) = 0u;
        REG16(sb + 0x16u) = val3;
        REG16(PWM4_BASE + 0x188u) |= (uint16_t)(1u << sm);              /* LDOK first */
        GPIO_DR(GPIO2_BASE) &= ~en_bit;                                 /* Active-LOW ON */
        REG16(PWM4_BASE + 0x188u) |= (uint16_t)(1u << (8u + sm));       /* Start RUN */
    }
}

static void haptics_stop_all(void) {
    haptics_set_motor(0, 0u);
    haptics_set_motor(1, 0u);
    g_rumble_l = 0u;
    g_rumble_r = 0u;
    g_rumble_wdog = 0u;
}

void bt_set_rumble(uint8_t left_pct, uint8_t right_pct) {
    int changed = (left_pct != g_rumble_l) || (right_pct != g_rumble_r);
    g_rumble_l = left_pct;
    g_rumble_r = right_pct;
    haptics_set_motor(0, left_pct);
    haptics_set_motor(1, right_pct);
    g_rumble_wdog = (left_pct || right_pct) ? 18000u : 0u; /* ~1.5 s safety watchdog @ ~12k ticks/s */
    if (changed && g_usb_cfg && g_usb_dtr) {
        uint16_t fsts = REG16(PWM4_BASE + 0x18Eu);
        uint16_t mctrl = REG16(PWM4_BASE + 0x188u);
        usb_cdc_puts("RUMBLE L="); usb_cdc_put_u32(left_pct);
        usb_cdc_puts(" R="); usb_cdc_put_u32(right_pct);
        usb_cdc_puts(" FSTS="); usb_cdc_put_hex8((uint8_t)(fsts & 0xFFu));
        usb_cdc_puts(" MC="); usb_cdc_put_hex8((uint8_t)(mctrl >> 8));
        usb_cdc_puts("\r\n");
    }
}

/* Battery Fuel Gauge (BQ2742X @ LPI2C1 0x55) + Charger (BQ25601 @ LPI2C1 0x6B) */
static uint16_t g_bat_soc = 0xFFFFu;
static uint16_t g_bat_mv = 0u;
static uint8_t g_chg_reg08 = 0xFFu;

static void bq2742x_wake_pulse(void) {
    /* GPIO2_28 (GPIO_B1_12) is BQ2742X GPOUT (slot_a_bruce.bin @ 0x60068a00):
     * drive HIGH -> LOW (~2 ms) -> HIGH (~2 ms) -> release Hi-Z input. */
    IOMUXC_GPR_GPR(1) &= ~(1u << 28);
    REG32(0x401F81ACu) = 5u;
    REG32(0x401F839Cu) = 0x10B0u;
    GPIO_DR(GPIO2_BASE) |= (1u << 28);
    GPIO_GDIR(GPIO2_BASE) |= (1u << 28);
    delay_cycles(200000u);
    GPIO_DR(GPIO2_BASE) &= ~(1u << 28);
    delay_cycles(200000u);
    GPIO_DR(GPIO2_BASE) |= (1u << 28);
    delay_cycles(200000u);
    GPIO_GDIR(GPIO2_BASE) &= ~(1u << 28);
}

static void lpuart3_drain_rx(void);

static void battery_poll_and_update(int log_now) {
    uint16_t soc = 0xFFFFu;
    uint16_t mv = 0u;
    uint8_t reg08 = 0xFFu;
    int soc_ok = (lpi2c_read_u16_le(LPI2C1_BASE, 0x55u, 0x1Cu, &soc) == 0 && soc <= 100u);
    lpuart3_drain_rx();
    delay_cycles(20000u); /* Respect BQ2742X t_BUF >= 66 us between commands */
    int mv_ok = (lpi2c_read_u16_le(LPI2C1_BASE, 0x55u, 0x04u, &mv) == 0 && mv >= 2500u && mv <= 5000u);
    lpuart3_drain_rx();
    delay_cycles(20000u);
    int chg_ok = (lpi2c_read_reg(LPI2C1_BASE, 0x6Bu, 0x08u, &reg08) == 0);
    lpuart3_drain_rx();

    if (soc_ok) g_bat_soc = soc;
    if (mv_ok) g_bat_mv = mv;
    if (chg_ok) g_chg_reg08 = reg08;

    uint8_t level_nibble = 0x80u; /* Full default */
    if (soc_ok) {
        if (soc >= 75u) level_nibble = 0x80u;
        else if (soc >= 50u) level_nibble = 0x60u;
        else if (soc >= 25u) level_nibble = 0x40u;
        else if (soc >= 10u) level_nibble = 0x20u;
        else level_nibble = 0x00u;
    } else if (mv_ok) {
        if (mv >= 4000u) level_nibble = 0x80u;
        else if (mv >= 3800u) level_nibble = 0x60u;
        else if (mv >= 3650u) level_nibble = 0x40u;
        else if (mv >= 3500u) level_nibble = 0x20u;
        else level_nibble = 0x00u;
    }

    uint8_t chg_bit = 0x00u;
    if (chg_ok) {
        uint8_t chrg_stat = (uint8_t)((reg08 >> 3) & 0x03u);
        uint8_t pg_stat = (uint8_t)((reg08 >> 2) & 0x01u);
        if (chrg_stat == 1u || chrg_stat == 2u || (pg_stat && soc_ok && soc >= 95u)) {
            chg_bit = 0x10u;
        }
    } else if (!soc_ok && !mv_ok) {
        chg_bit = 0x10u; /* Fallback 0x90 when neither gauge nor charger responds */
    }
    g_bt.battery_byte = (uint8_t)(level_nibble | chg_bit);

    if (log_now && g_usb_cfg && g_usb_dtr) {
        usb_cdc_puts("BAT soc=");
        if (soc_ok) usb_cdc_put_u32(soc); else usb_cdc_puts("--");
        usb_cdc_puts("% mv=");
        if (mv_ok) usb_cdc_put_u32(mv); else usb_cdc_puts("--");
        usb_cdc_puts(" chg08=");
        if (chg_ok) usb_cdc_put_hex8(reg08); else usb_cdc_puts("--");
        usb_cdc_puts(" hid=0x"); usb_cdc_put_hex8(g_bt.battery_byte);
        usb_cdc_puts("\r\n");
    }
}


static uint8_t g_rx_ring[512];
static volatile uint32_t g_rx_head = 0u;
static volatile uint32_t g_rx_tail = 0u;

static void lpuart3_drain_rx(void) {
    for (uint32_t i = 0u; i < 16u; ++i) {
        uint32_t stat = LPUART_STAT(LPUART3_BASE);
        if (stat & (1u << 19)) {
            LPUART_STAT(LPUART3_BASE) = (1u << 19);
        }
        if ((stat & (1u << 21)) == 0u) {
            break;
        }
        uint8_t b = (uint8_t)(LPUART_DATA(LPUART3_BASE) & 0xFFu);
        uint32_t next = (g_rx_head + 1u) & 511u;
        if (next != g_rx_tail) {
            g_rx_ring[g_rx_head] = b;
            g_rx_head = next;
        }
    }
}

static void lpuart3_putc(uint8_t ch) {
    while ((LPUART_STAT(LPUART3_BASE) & (1u << 23)) == 0u) {
        lpuart3_drain_rx();
    }
    LPUART_DATA(LPUART3_BASE) = ch;
}

void bt_uart_write(const uint8_t *data, uint32_t len) {
    for (uint32_t i = 0u; i < len; ++i) {
        lpuart3_putc(data[i]);
    }
}

static int lpuart3_getc_timeout(uint8_t *out, uint32_t max_loops) {
    for (uint32_t i = 0u; i < max_loops; ++i) {
        usb_cdc_poll();
        lpuart3_drain_rx();
        if (g_rx_tail != g_rx_head) {
            *out = g_rx_ring[g_rx_tail];
            g_rx_tail = (g_rx_tail + 1u) & 511u;
            return 0;
        }
    }
    return -1;
}

static uint32_t hci_read_event(uint8_t *evt, uint32_t max_len, uint32_t timeout) {
    uint8_t b = 0u;
    for (uint32_t tries = 0u; tries < 32u; ++tries) {
        if (lpuart3_getc_timeout(&b, timeout) != 0) {
            return 0u;
        }
        if (b == 0x04u) {
            break;
        }
    }
    if (b != 0x04u) {
        return 0u;
    }
    uint8_t hdr[2] = { 0 };
    if (lpuart3_getc_timeout(&hdr[0], timeout) != 0 ||
        lpuart3_getc_timeout(&hdr[1], timeout) != 0) {
        return 0u;
    }
    uint32_t plen = hdr[1];
    if (2u + plen > max_len) {
        return 0u;
    }
    evt[0] = hdr[0];
    evt[1] = hdr[1];
    for (uint32_t i = 0u; i < plen; ++i) {
        if (lpuart3_getc_timeout(&evt[2u + i], timeout) != 0) {
            return 0u;
        }
    }
    return 2u + plen;
}

static int hci_send_cmd(uint16_t opcode, const uint8_t *params, uint8_t len,
                        uint8_t *evt_out, uint32_t max_evt) {
    uint8_t evt_buf[64];
    uint8_t *eb = (evt_out && max_evt >= 16u) ? evt_out : evt_buf;
    uint32_t ecap = (evt_out && max_evt >= 16u) ? max_evt : (uint32_t)sizeof(evt_buf);

    lpuart3_putc(0x01u);
    lpuart3_putc((uint8_t)(opcode & 0xFFu));
    lpuart3_putc((uint8_t)(opcode >> 8));
    lpuart3_putc(len);
    for (uint8_t i = 0u; i < len; ++i) {
        lpuart3_putc(params[i]);
    }
    while ((LPUART_STAT(LPUART3_BASE) & (1u << 22)) == 0u) {}

    for (uint32_t r = 0u; r < 8u; ++r) {
        uint32_t elen = hci_read_event(eb, ecap, 4000000u);
        if (elen == 0u) {
            return -1;
        }
        if (eb[0] == 0x0Eu && elen >= 6u &&
            eb[3] == (uint8_t)(opcode & 0xFFu) &&
            eb[4] == (uint8_t)(opcode >> 8)) {
            return (eb[5] == 0x00u) ? 0 : -2;
        }
    }
    return -1;
}

#if STADIA_DEBUG_CONSOLE
typedef struct {
    const char *name;
    uint8_t port_idx;
    uint8_t pin;
    uint32_t mux_reg;
} probe_pin_t;

/* Excluded from sweep: GPIO2_10 (L2/R2 Hall EN), GPIO2_28 (BQ2742X GPOUT), GPIO4_03 (PMIC_KILL companion) */
static const probe_pin_t k_probe_pins[12] = {
    { "GPIO1_01", 0u,  1u, 0x401F80C0u },
    { "GPIO1_03", 0u,  3u, 0x401F80C8u },
    { "GPIO1_14", 0u, 14u, 0x401F80F4u },
    { "GPIO2_06", 1u,  6u, 0x401F8154u },
    { "GPIO2_07", 1u,  7u, 0x401F8158u },
    { "GPIO2_24", 1u, 24u, 0x401F819Cu },
    { "GPIO3_21", 2u, 21u, 0x401F80A0u },
    { "GPIO3_23", 2u, 23u, 0x401F80A8u },
    { "GPIO3_26", 2u, 26u, 0x401F80B4u },
    { "GPIO4_27", 3u, 27u, 0x401F8080u },
    { "GPIO4_28", 3u, 28u, 0x401F8084u },
    { "GPIO4_29", 3u, 29u, 0x401F8088u },
};

static void probe_drive_pin(uint32_t idx, int val) {
    const probe_pin_t *p = &k_probe_pins[idx];
    uint32_t gbase = k_gpio_bases[p->port_idx];
    uint32_t mask = 1u << p->pin;
    *(volatile uint32_t *)p->mux_reg = 5u;
    if (val) {
        GPIO_DR(gbase) |= mask;
    } else {
        GPIO_DR(gbase) &= ~mask;
    }
    GPIO_GDIR(gbase) |= mask;
}

static void probe_release_pin(uint32_t idx) {
    const probe_pin_t *p = &k_probe_pins[idx];
    GPIO_GDIR(k_gpio_bases[p->port_idx]) &= ~(1u << p->pin);
}

static void probe_print_adc(const char *tag, const char *name, int level) {
    uint16_t in8 = adc_read_avg(ADC1_BASE, 8u);
    uint16_t in13 = adc_read_avg(ADC1_BASE, 13u);
    uint16_t lx = adc_read_avg(ADC1_BASE, 11u);
    usb_cdc_puts(tag);
    usb_cdc_puts(" ");
    usb_cdc_puts(name);
    usb_cdc_puts("=");
    usb_cdc_puts(level < 0 ? "Z" : (level ? "1" : "0"));
    usb_cdc_puts(" IN8="); usb_cdc_put_u32(in8);
    usb_cdc_puts(" IN13="); usb_cdc_put_u32(in13);
    usb_cdc_puts(" LX="); usb_cdc_put_u32(lx);
    usb_cdc_puts("\r\n");
    usb_cdc_poll();
}

static void i2c_dump_chip(uint32_t bus_num, uint32_t base, uint8_t addr7) {
    usb_cdc_puts("I2C CHIP bus="); usb_cdc_put_u32(bus_num);
    usb_cdc_puts(" addr=0x"); usb_cdc_put_hex8(addr7);
    usb_cdc_puts("\r\n");
    for (uint32_t row = 0u; row < 0x80u; row += 16u) {
        usb_cdc_puts("  "); usb_cdc_put_hex8((uint8_t)row); usb_cdc_puts(":");
        for (uint32_t col = 0u; col < 16u; ++col) {
            uint8_t v = 0u;
            usb_cdc_puts(" ");
            if (lpi2c_read_reg(base, addr7, (uint8_t)(row + col), &v) == 0) {
                usb_cdc_put_hex8(v);
            } else {
                usb_cdc_puts("--");
            }
        }
        usb_cdc_puts("\r\n");
        usb_cdc_poll();
    }
}

static void i2c_scan_and_dump(void) {
    usb_cdc_puts("I2C SCAN START\r\n");
    for (uint32_t idx = 0u; idx < 2u; ++idx) {
        uint32_t base = k_i2c_candidates[idx].base;
        i2c_ensure_bus(idx);
        for (uint8_t addr = 0x08u; addr <= 0x77u; ++addr) {
            uint8_t v0 = 0u;
            if (lpi2c_read_reg(base, addr, 0x00u, &v0) == 0) {
                i2c_dump_chip(idx + 1u, base, addr);
            }
            usb_cdc_poll();
        }
    }
    usb_cdc_puts("I2C SCAN DONE\r\n");
}

static int parse_hex_tok(const char **p, uint32_t *out) {
    const char *s = *p;
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    if (*s == '\0') {
        return -1;
    }
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }
    uint32_t v = 0u;
    int digits = 0;
    while (*s != '\0' && *s != ' ' && *s != '\t') {
        uint8_t d;
        if (*s >= '0' && *s <= '9') d = (uint8_t)(*s - '0');
        else if (*s >= 'a' && *s <= 'f') d = (uint8_t)(10 + *s - 'a');
        else if (*s >= 'A' && *s <= 'F') d = (uint8_t)(10 + *s - 'A');
        else return -1;
        v = (v << 4) | d;
        digits++;
        s++;
    }
    if (digits == 0) {
        return -1;
    }
    *p = s;
    *out = v;
    return 0;
}

static void handle_w_cmd(const char *line) {
    const char *p = line + 1;
    uint32_t bus = 0u, addr = 0u, reg = 0u, val = 0u;
    if (parse_hex_tok(&p, &bus) < 0 || parse_hex_tok(&p, &addr) < 0 ||
        parse_hex_tok(&p, &reg) < 0 || parse_hex_tok(&p, &val) < 0 ||
        bus < 1u || bus > 2u) {
        usb_cdc_puts("W ERR usage: w <1|2> <addr> <reg> <val>\r\n");
        return;
    }
    uint32_t base = k_i2c_candidates[bus - 1u].base;
    i2c_ensure_bus(bus - 1u);
    int rc = lpi2c_write_reg(base, (uint8_t)addr, (uint8_t)reg, (uint8_t)val);
    for (uint32_t w = 0u; w < 50u; ++w) {
        delay_cycles(120000u);
        lpuart3_drain_rx();
        usb_cdc_poll();
    }
    uint8_t rd = 0xEEu;
    int rrc = lpi2c_read_reg(base, (uint8_t)addr, (uint8_t)reg, &rd);
    uint16_t in8 = adc_read_avg(ADC1_BASE, 8u);
    uint16_t in13 = adc_read_avg(ADC1_BASE, 13u);
    uint16_t lx = adc_read_avg(ADC1_BASE, 11u);
    usb_cdc_puts("W bus="); usb_cdc_put_u32(bus);
    usb_cdc_puts(" addr="); usb_cdc_put_hex8((uint8_t)addr);
    usb_cdc_puts(" reg="); usb_cdc_put_hex8((uint8_t)reg);
    usb_cdc_puts(" val="); usb_cdc_put_hex8((uint8_t)val);
    usb_cdc_puts(" rc="); usb_cdc_put_u32((uint32_t)(rc == 0 ? 0 : 1));
    usb_cdc_puts(" rd=");
    if (rrc == 0) usb_cdc_put_hex8(rd); else usb_cdc_puts("--");
    usb_cdc_puts(" IN8="); usb_cdc_put_u32(in8);
    usb_cdc_puts(" IN13="); usb_cdc_put_u32(in13);
    usb_cdc_puts(" LX="); usb_cdc_put_u32(lx);
    usb_cdc_puts("\r\n");
}

static int parse_dec_tok(const char **p, uint32_t *out) {
    const char *s = *p;
    while (*s == ' ' || *s == '\t') s++;
    if (*s < '0' || *s > '9') return -1;
    uint32_t v = 0u;
    while (*s >= '0' && *s <= '9') {
        v = (v * 10u) + (uint32_t)(*s - '0');
        s++;
    }
    *p = s;
    *out = v;
    return 0;
}

static void handle_m_cmd(const char *line) {
    const char *p = line + 1;
    uint32_t lv = 0u, rv = 0u;
    if (parse_dec_tok(&p, &lv) < 0 || parse_dec_tok(&p, &rv) < 0 || lv > 100u || rv > 100u) {
        usb_cdc_puts("M ERR usage: m <L 0..100> <R 0..100>\r\n");
        return;
    }
    bt_set_rumble((uint8_t)lv, (uint8_t)rv);
}

static void hall_probe_poll(void) {
    static char cmd_buf[48];
    static uint32_t cmd_len = 0u;
    static int in_line = 0;
    uint8_t ch = 0u;
    while (usb_cdc_getc(&ch) == 0) {
        if (in_line) {
            if (ch == '\r' || ch == '\n') {
                cmd_buf[cmd_len] = '\0';
                in_line = 0;
                cmd_len = 0u;
                if (cmd_buf[0] == 'w') {
                    handle_w_cmd(cmd_buf);
                } else if (cmd_buf[0] == 'm') {
                    handle_m_cmd(cmd_buf);
                }
            } else if (cmd_len + 1u < sizeof(cmd_buf)) {
                cmd_buf[cmd_len++] = (char)ch;
            }
            continue;
        }
        if (ch == 'w' || ch == 'm') {
            cmd_buf[0] = (char)ch;
            cmd_len = 1u;
            in_line = 1;
        } else if (ch == 'b') {
            bq2742x_wake_pulse();
            delay_cycles(500000u);
            i2c_ensure_bus(0u);
            battery_poll_and_update(1);
        } else if (ch == 'p') {
            haptics_print_regs("PWM REGS:");
        } else if (ch == 'i') {
            i2c_scan_and_dump();
        } else if (ch == 's') {
            usb_cdc_puts("SWEEP START\r\n");
            for (uint32_t i = 0u; i < 12u; ++i) {
                for (int lvl = 1; lvl >= 0; --lvl) {
                    probe_drive_pin(i, lvl);
                    for (uint32_t w = 0u; w < 100u; ++w) {
                        delay_cycles(120000u);
                        lpuart3_drain_rx();
                        usb_cdc_poll();
                    }
                    probe_print_adc("SWEEP", k_probe_pins[i].name, lvl);
                }
                probe_release_pin(i);
            }
            usb_cdc_puts("SWEEP DONE\r\n");
        } else if (ch == 'r') {
            for (uint32_t i = 0u; i < 12u; ++i) {
                probe_release_pin(i);
            }
            probe_print_adc("PROBE", "ALL", -1);
        } else if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'b')) {
            uint32_t idx = (ch >= 'a') ? (10u + (uint32_t)(ch - 'a')) : (uint32_t)(ch - '0');
            probe_drive_pin(idx, 1);
            delay_cycles(500000u);
            probe_print_adc("PROBE", k_probe_pins[idx].name, 1);
        } else if (ch >= 'A' && ch <= 'L') {
            uint32_t idx = (uint32_t)(ch - 'A');
            probe_drive_pin(idx, 0);
            delay_cycles(500000u);
            probe_print_adc("PROBE", k_probe_pins[idx].name, 0);
        }
    }
}
#else
static void hall_probe_poll(void) {}
#endif

static void lp5562_set_rgbw(uint32_t base, uint8_t addr,
                            uint8_t r, uint8_t g, uint8_t b, uint8_t w);

static int bt_boot_and_advertise(int has_led, uint32_t i2c_base, uint8_t lp_addr) {
    uint8_t evt[32] = { 0 };

    /* Route 24 MHz osc_clk / 1 to UART_CLK_ROOT */
    CCM_CSCDR1 = (CCM_CSCDR1 & ~0x7Fu) | (1u << 6);

    /* BCM43458F BT_REG_ON (GPIO_EMC_34 = GPIO3_20) & BT_DEV_WAKE (GPIO_EMC_41 = GPIO3_27) */
    IOMUXC_GPR_GPR(2) &= ~((1u << 20) | (1u << 27));
    REG32(0x401F809Cu) = 5u;
    REG32(0x401F828Cu) = 0x10B0u;
    REG32(0x401F80B8u) = 5u;
    REG32(0x401F82A8u) = 0x10B0u;
    GPIO_DR(GPIO3_BASE) &= ~((1u << 20) | (1u << 27));
    GPIO_GDIR(GPIO3_BASE) |= (1u << 20) | (1u << 27);

    /* Boot strap (0x6006ec50): drive GPIO_EMC_15 (GPIO4_15 / CTS_B) LOW during BT_REG_ON */
    IOMUXC_GPR_GPR(3) &= ~(1u << 15);
    REG32(0x401F8050u) = 5u;
    REG32(0x401F8240u) = 0x10B0u;
    GPIO_DR(GPIO4_BASE) &= ~(1u << 15);
    GPIO_GDIR(GPIO4_BASE) |= (1u << 15);

    /* Hold BT_REG_ON low ~50 ms, then drive BT_REG_ON high for ~50 ms */
    delay_cycles(5000000u);
    GPIO_DR(GPIO3_BASE) |= (1u << 20);
    delay_cycles(5000000u);

    /* Release strap (0x6006ec90): switch GPIO_EMC_15 to ALT2 (LPUART3_CTS_B) */
    GPIO_GDIR(GPIO4_BASE) &= ~(1u << 15);
    REG32(0x401F8050u) = 2u;      /* CTS_B */
    REG32(0x401F8534u) = 0u;      /* LPUART3_CTS_B_SELECT_INPUT */
    REG32(0x401F8240u) = 0x10B0u;

    /* Configure remaining LPUART3 pins: GPIO_EMC_13 (TX), 14 (RX), 16 (RTS_B) ALT2 */
    REG32(0x401F8048u) = 2u;      /* TX */
    REG32(0x401F853Cu) = 1u;      /* LPUART3_TX_SELECT_INPUT */
    REG32(0x401F8238u) = 0x10B0u;
    REG32(0x401F804Cu) = 2u;      /* RX */
    REG32(0x401F8538u) = 1u;      /* LPUART3_RX_SELECT_INPUT */
    REG32(0x401F823Cu) = 0xF0B0u;
    REG32(0x401F8054u) = 2u;      /* RTS_B */
    REG32(0x401F8244u) = 0x10B0u;

    /* Reset and initialize LPUART3: 24 MHz / (16 * 13) = 115384 baud, RXRTSE, FIFO enabled */
    LPUART_GLOBAL(LPUART3_BASE) = (1u << 1);
    delay_cycles(1000u);
    LPUART_GLOBAL(LPUART3_BASE) = 0u;

    uint32_t baud_reg = (15u << 24) | 13u;
    LPUART_BAUD(LPUART3_BASE) = baud_reg;
    LPUART_MODIR(LPUART3_BASE) = (1u << 3); /* RXRTSE at +0x24 */
    LPUART_FIFO(LPUART3_BASE) = 0xC088u;    /* TXFLUSH | RXFLUSH | TXFE | RXFE at +0x28 */
    LPUART_STAT(LPUART3_BASE) = 0xC01FC000u;
    LPUART_CTRL(LPUART3_BASE) = (1u << 19) | (1u << 18); /* TE | RE */
    delay_cycles(2000000u);

    while (LPUART_STAT(LPUART3_BASE) & (1u << 21)) {
        (void)LPUART_DATA(LPUART3_BASE);
    }
    LPUART_STAT(LPUART3_BASE) = 0xC01FC000u;
    DIAG_STATUS->bt_uart_baud_reg = baud_reg;

    /* 1. Initial HCI_Reset */
    if (hci_send_cmd(0x0C03u, 0, 0u, evt, sizeof(evt)) != 0) {
        return 0;
    }

    /* 2. Broadcom Download_Minidriver (0xFC2E) + 228 HCD packets */
    if (hci_send_cmd(0xFC2Eu, 0, 0u, evt, sizeof(evt)) != 0) {
        return 0;
    }
    delay_cycles(5000000u);

    uint32_t pos = 0u;
    uint32_t pkt = 0u;
    while (pos + 3u <= k_bcm43458f_hcd_len) {
        uint16_t op = (uint16_t)k_bcm43458f_hcd[pos] |
                      ((uint16_t)k_bcm43458f_hcd[pos + 1u] << 8);
        uint8_t plen = k_bcm43458f_hcd[pos + 2u];
        if (pos + 3u + plen > k_bcm43458f_hcd_len) {
            return 0;
        }
        if (hci_send_cmd(op, &k_bcm43458f_hcd[pos + 3u], plen, evt, sizeof(evt)) != 0) {
            return 0;
        }
        pos += 3u + plen;
        ++pkt;
        if (has_led && (pkt & 15u) == 0u) {
            uint8_t g = (pkt & 16u) ? 0x80u : 0x00u;
            lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, g, 0x00u, 0x00u);
        }
    }

    /* 3. Wait ~250 ms after Launch_RAM, then post-patch HCI_Reset */
    delay_cycles(25000000u);
    while (LPUART_STAT(LPUART3_BASE) & (1u << 21)) {
        (void)LPUART_DATA(LPUART3_BASE);
    }
    LPUART_STAT(LPUART3_BASE) = 0xC01FC000u;

    if (hci_send_cmd(0x0C03u, 0, 0u, evt, sizeof(evt)) != 0) {
        return 0;
    }

    /* 4. Unmask all HCI events (including SSP 0x31..0x36), then set CoD, Name, EIR, SSP, Scan */
    static const uint8_t evt_mask[8] = {
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x3Fu
    };
    (void)hci_send_cmd(0x0C01u, evt_mask, 8u, evt, sizeof(evt));

    static const uint8_t cod[3] = { 0x08u, 0x25u, 0x00u };
    if (hci_send_cmd(0x0C24u, cod, 3u, evt, sizeof(evt)) != 0) {
        return 0;
    }

    uint8_t name_buf[248];
    static const char k_name[] = "Pro Controller";
    for (uint32_t i = 0u; i < sizeof(name_buf); ++i) {
        name_buf[i] = (i < sizeof(k_name) - 1u) ? (uint8_t)k_name[i] : 0u;
    }
    if (hci_send_cmd(0x0C13u, name_buf, 248u, evt, sizeof(evt)) != 0) {
        return 0;
    }

    static const uint8_t inq_mode = 0x02u; /* Inquiry with RSSI + EIR */
    (void)hci_send_cmd(0x0C45u, &inq_mode, 1u, evt, sizeof(evt));

    uint8_t eir[241];
    for (uint32_t i = 0u; i < sizeof(eir); ++i) {
        eir[i] = 0u;
    }
    /* eir[0] = FEC_Required (0); AD1: Complete Local Name "Pro Controller" (len 15); AD2: HID 0x1124 */
    eir[1] = 15u;
    eir[2] = 0x09u;
    for (uint32_t i = 0u; i < 14u; ++i) {
        eir[3u + i] = (uint8_t)k_name[i];
    }
    eir[17] = 3u;
    eir[18] = 0x03u;
    eir[19] = 0x24u;
    eir[20] = 0x11u;
    (void)hci_send_cmd(0x0C52u, eir, 241u, evt, sizeof(evt));

    static const uint8_t ssp_en = 0x01u;
    (void)hci_send_cmd(0x0C56u, &ssp_en, 1u, evt, sizeof(evt));

    /* Enable Role Switch (bit 0) + Sniff Mode (bit 2) in default link policy */
    static const uint8_t link_pol[2] = { 0x05u, 0x00u };
    (void)hci_send_cmd(0x080Fu, link_pol, 2u, evt, sizeof(evt));

    static const uint8_t scan_both = 0x03u; /* Inquiry + Page Scan */
    if (hci_send_cmd(0x0C1Au, &scan_both, 1u, evt, sizeof(evt)) != 0) {
        return 0;
    }

    /* 5. Read BD_ADDR for diagnostics and HID device info */
    uint8_t bd[6] = { 0 };
    if (hci_send_cmd(0x1009u, 0, 0u, evt, sizeof(evt)) == 0) {
        for (uint32_t i = 0u; i < 6u; ++i) {
            bd[i] = evt[6u + i];
        }
        DIAG_STATUS->bt_hci_rx0 = (uint32_t)evt[6] | ((uint32_t)evt[7] << 8) |
                                  ((uint32_t)evt[8] << 16) | ((uint32_t)evt[9] << 24);
        DIAG_STATUS->bt_hci_rx1 = (uint32_t)evt[10] | ((uint32_t)evt[11] << 8);
    }
    bt_hid_init_state(bd);
    DIAG_STATUS->bt_hci_ok = 1u;
    return 1;
}

static void hci_send_cmd_nb(uint16_t opcode, const uint8_t *params, uint8_t len) {
    lpuart3_putc(0x01u);
    lpuart3_putc((uint8_t)(opcode & 0xFFu));
    lpuart3_putc((uint8_t)(opcode >> 8));
    lpuart3_putc(len);
    for (uint8_t i = 0u; i < len; ++i) {
        lpuart3_putc(params[i]);
    }
}

static void log_hci_pkt(const char *tag, const uint8_t *buf, uint32_t len) {
    if (!g_usb_cfg || !g_usb_dtr) {
        return;
    }
    /* Redact 16-byte Link Key payload in HCI_Link_Key_Notification (0x18) */
    if (tag[0] == 'H' && len >= 25u && buf[0] == 0x18u) {
        usb_cdc_puts(tag);
        for (uint32_t i = 0u; i < 8u; ++i) {
            usb_cdc_puts(" ");
            usb_cdc_put_hex8(buf[i]);
        }
        usb_cdc_puts(" [KEY-REDACTED] ");
        usb_cdc_put_hex8(buf[24]);
        usb_cdc_puts("\r\n");
        return;
    }
    usb_cdc_puts(tag);
    uint32_t n = (len > 32u) ? 32u : len;
    for (uint32_t i = 0u; i < n; ++i) {
        usb_cdc_puts(" ");
        usb_cdc_put_hex8(buf[i]);
    }
    if (len > n) {
        usb_cdc_puts(" ...");
    }
    usb_cdc_puts("\r\n");
}

/* RAM-only Link Key cache (up to 4 peers per boot session) */
typedef struct {
    uint8_t valid;
    uint8_t bd_addr[6];
    uint8_t link_key[16];
} bt_link_key_t;

static bt_link_key_t g_link_keys[4];
static uint8_t g_link_key_next = 0u;

static int bd_addr_eq(const uint8_t a[6], const uint8_t b[6]) {
    for (uint32_t i = 0u; i < 6u; ++i) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void bt_link_key_save(const uint8_t bd[6], const uint8_t key[16]) {
    int slot = -1;
    for (int i = 0; i < 4; ++i) {
        if (g_link_keys[i].valid && bd_addr_eq(g_link_keys[i].bd_addr, bd)) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < 4; ++i) {
            if (!g_link_keys[i].valid) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        slot = (int)(g_link_key_next & 3u);
        g_link_key_next++;
    }
    g_link_keys[slot].valid = 1u;
    for (uint32_t i = 0u; i < 6u; ++i) g_link_keys[slot].bd_addr[i] = bd[i];
    for (uint32_t i = 0u; i < 16u; ++i) g_link_keys[slot].link_key[i] = key[i];
    if (g_usb_cfg && g_usb_dtr) {
        usb_cdc_puts("BT LINK KEY CACHED slot=");
        usb_cdc_put_u32((uint32_t)slot);
        usb_cdc_puts("\r\n");
    }
}

static int bt_link_key_find(const uint8_t bd[6], uint8_t key_out[16]) {
    for (int i = 0; i < 4; ++i) {
        if (g_link_keys[i].valid && bd_addr_eq(g_link_keys[i].bd_addr, bd)) {
            for (uint32_t j = 0u; j < 16u; ++j) key_out[j] = g_link_keys[i].link_key[j];
            return 1;
        }
    }
    return 0;
}

static void bt_link_key_clear_peer(const uint8_t bd[6]) {
    for (int i = 0; i < 4; ++i) {
        if (g_link_keys[i].valid && bd_addr_eq(g_link_keys[i].bd_addr, bd)) {
            g_link_keys[i].valid = 0u;
            for (uint32_t j = 0u; j < 16u; ++j) g_link_keys[i].link_key[j] = 0u;
        }
    }
}

static void bt_link_key_clear_all(void) {
    for (int i = 0; i < 4; ++i) {
        g_link_keys[i].valid = 0u;
        for (uint32_t j = 0u; j < 16u; ++j) g_link_keys[i].link_key[j] = 0u;
    }
}

void bt_log_acl_tx(uint16_t cid, const uint8_t *payload, uint16_t plen) {
    if (!g_usb_cfg || !g_usb_dtr) {
        return;
    }
    /* Log all signaling/SDP/HID-control/0x21 replies; skip high-rate 0x30 streaming */
    if (cid == g_bt.l2cap_host_cid[2] && plen >= 2u && payload[1] == 0x30u) {
        return;
    }
    usb_cdc_puts("ACL TX[");
    usb_cdc_put_hex8((uint8_t)(cid >> 8));
    usb_cdc_put_hex8((uint8_t)(cid & 0xFFu));
    usb_cdc_puts("]:");
    uint32_t n = (plen > 24u) ? 24u : plen;
    for (uint32_t i = 0u; i < n; ++i) {
        usb_cdc_puts(" ");
        usb_cdc_put_hex8(payload[i]);
    }
    if (plen > n) {
        usb_cdc_puts(" ...");
    }
    usb_cdc_puts("\r\n");
}

static void bt_handle_hci_event(const uint8_t *buf, uint32_t len) {
    if (len < 2u) {
        return;
    }
    uint8_t evt = buf[0];
    if (evt != 0x13u) {
        log_hci_pkt("HCI EVT:", buf, len);
    }
    if (evt == 0x04u && len >= 12u) {
        /* HCI_Connection_Request -> Accept as Peripheral (role = 0x01) */
        uint8_t p[7];
        for (uint32_t i = 0u; i < 6u; ++i) {
            p[i] = buf[2u + i];
        }
        p[6] = 0x01u;
        hci_send_cmd_nb(0x0409u, p, 7u);
    } else if (evt == 0x03u && len >= 13u) {
        /* HCI_Connection_Complete */
        if (buf[2] == 0x00u) {
            g_bt.acl_handle = (uint16_t)buf[3] | ((uint16_t)(buf[4] & 0x0Fu) << 8);
            for (uint32_t i = 0u; i < 6u; ++i) {
                g_bt.peer_bd_addr[i] = buf[5u + i];
            }
            g_bt.connected = 1u;
        }
    } else if (evt == 0x05u && len >= 6u) {
        /* HCI_Disconnection_Complete: stop motors, reset state, re-enable scan */
        haptics_stop_all();
        bt_hid_init_state(g_bt.bd_addr);
        uint8_t scan_both = 0x03u;
        hci_send_cmd_nb(0x0C1Au, &scan_both, 1u);
    } else if (evt == 0x06u && len >= 5u) {
        /* HCI_Authentication_Complete: evict stale cached key if auth failed */
        if (buf[2] != 0x00u && g_bt.connected) {
            bt_link_key_clear_peer(g_bt.peer_bd_addr);
            if (g_usb_cfg && g_usb_dtr) {
                usb_cdc_puts("BT AUTH FAIL -> EVICTED LINK KEY\r\n");
            }
        }
    } else if (evt == 0x17u && len >= 8u) {
        /* HCI_Link_Key_Request -> Reply from RAM cache if present, else Negative Reply */
        uint8_t p[22];
        if (bt_link_key_find(&buf[2], &p[6])) {
            for (uint32_t i = 0u; i < 6u; ++i) p[i] = buf[2u + i];
            hci_send_cmd_nb(0x040Bu, p, 22u);
            if (g_usb_cfg && g_usb_dtr) {
                usb_cdc_puts("BT LINK KEY HIT -> FAST RECONNECT\r\n");
            }
        } else {
            hci_send_cmd_nb(0x040Cu, &buf[2], 6u);
        }
    } else if (evt == 0x18u && len >= 25u) {
        /* HCI_Link_Key_Notification -> Cache in RAM for same-session reconnect */
        bt_link_key_save(&buf[2], &buf[8]);
    } else if (evt == 0x16u && len >= 8u) {
        /* HCI_PIN_Code_Request -> Reply "0000" */
        uint8_t p[23];
        for (uint32_t i = 0u; i < 6u; ++i) {
            p[i] = buf[2u + i];
        }
        p[6] = 4u;
        p[7] = '0'; p[8] = '0'; p[9] = '0'; p[10] = '0';
        for (uint32_t i = 11u; i < 23u; ++i) {
            p[i] = 0u;
        }
        hci_send_cmd_nb(0x040Du, p, 23u);
    } else if (evt == 0x13u) {
        /* HCI_Number_Of_Completed_Packets */
        bt_handle_num_completed_packets(buf, len);
    } else if (evt == 0x31u && len >= 8u) {
        /* HCI_IO_Capability_Request -> NoInputNoOutput (0x03), OOB=0, Auth=0x04 (General Bonding) */
        uint8_t p[9];
        for (uint32_t i = 0u; i < 6u; ++i) {
            p[i] = buf[2u + i];
        }
        p[6] = 0x03u;
        p[7] = 0x00u;
        p[8] = 0x04u;
        hci_send_cmd_nb(0x042Bu, p, 9u);
    } else if (evt == 0x33u && len >= 8u) {
        /* HCI_User_Confirmation_Request -> Positive Reply (Just Works) */
        hci_send_cmd_nb(0x042Cu, &buf[2], 6u);
    }
}

static void bt_poll_uart(const pro_input_t *in) {
    static uint8_t rx_type = 0u;
    static uint8_t rx_buf[264];
    static uint32_t rx_pos = 0u;
    static uint32_t rx_total = 0u;
    static uint32_t rx_need = 0u;

    lpuart3_drain_rx();
    while (g_rx_tail != g_rx_head) {
        uint8_t b = g_rx_ring[g_rx_tail];
        g_rx_tail = (g_rx_tail + 1u) & 511u;
        if (rx_type == 0u) {
            if (b == 0x04u) {
                rx_type = 0x04u;
                rx_pos = 0u;
                rx_total = 0u;
                rx_need = 2u;
            } else if (b == 0x02u) {
                rx_type = 0x02u;
                rx_pos = 0u;
                rx_total = 0u;
                rx_need = 4u;
            }
            continue;
        }
        rx_total++;
        if (rx_pos < sizeof(rx_buf)) {
            rx_buf[rx_pos++] = b;
        }
        if (rx_type == 0x04u && rx_total == 2u) {
            rx_need = 2u + (uint32_t)rx_buf[1];
        } else if (rx_type == 0x02u && rx_total == 4u) {
            uint16_t acl_len = (uint16_t)rx_buf[2] | ((uint16_t)rx_buf[3] << 8);
            rx_need = 4u + (uint32_t)acl_len;
        }
        if (rx_total >= rx_need) {
            if (rx_total <= sizeof(rx_buf)) {
                if (rx_type == 0x04u) {
                    bt_handle_hci_event(rx_buf, rx_pos);
                } else if (rx_type == 0x02u) {
                    /* Skip flooding CDC with neutral Switch A2 10 keepalive frames */
                    int is_neutral_rumble = (rx_pos == 19u && rx_buf[6] == 0x42u && rx_buf[7] == 0x00u &&
                                             rx_buf[8] == 0xA2u && rx_buf[9] == 0x10u &&
                                             rx_buf[11] == 0x00u && rx_buf[12] == 0x01u &&
                                             rx_buf[13] == 0x40u && rx_buf[14] == 0x40u &&
                                             rx_buf[15] == 0x00u && rx_buf[16] == 0x01u &&
                                             rx_buf[17] == 0x40u && rx_buf[18] == 0x40u);
                    if (!is_neutral_rumble) {
                        log_hci_pkt("ACL RX:", rx_buf, rx_pos);
                    }
                    bt_handle_acl(rx_buf, rx_pos, in);
                }
            }
            rx_type = 0u;
            rx_pos = 0u;
            rx_total = 0u;
            rx_need = 0u;
        }
        lpuart3_drain_rx();
    }
}

static void lp5562_set_rgbw(uint32_t base, uint8_t addr,
                            uint8_t r, uint8_t g, uint8_t b, uint8_t w) {
    lpi2c_write_reg(base, addr, 0x02u, b);
    lpi2c_write_reg(base, addr, 0x03u, g);
    lpi2c_write_reg(base, addr, 0x04u, r);
    lpi2c_write_reg(base, addr, 0x0Eu, w);
}

static void stadia_power_off(int has_bt, int has_led, uint32_t i2c_base, uint8_t lp_addr) {
    haptics_stop_all();
    if (has_bt && g_bt.connected) {
        uint8_t disc[3] = {
            (uint8_t)(g_bt.acl_handle & 0xFFu),
            (uint8_t)((g_bt.acl_handle >> 8) & 0x0Fu),
            0x13u /* Remote User Terminated Connection */
        };
        hci_send_cmd_nb(0x0406u, disc, 3u);
    }
    if (g_usb_cfg && g_usb_dtr) {
        usb_cdc_puts("POWER OFF (PMIC_KILL)\r\n");
    }
    if (has_led) {
        lp5562_set_rgbw(i2c_base, lp_addr, 0xFFu, 0x00u, 0x00u, 0x00u);
    }
    for (uint32_t w = 0u; w < 80u; ++w) {
        usb_cdc_poll();
        delay_cycles(200000u);
    }
    if (has_led) {
        lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, 0x00u, 0x00u, 0x00u);
    }
    /* Stock PMIC_KILL sequence (slot_a_bruce.bin @ 0x600510c0):
     * drive GPIO4_03 (GPIO_EMC_03) LOW, then GPIO4_02 (GPIO_EMC_02, PMIC_KILL) HIGH. */
    IOMUXC_GPR_GPR(3) &= ~((1u << 2) | (1u << 3));
    REG32(0x401F8020u) = 5u;      /* GPIO_EMC_03 -> GPIO4_03 */
    REG32(0x401F8210u) = 0x10B0u;
    REG32(0x401F801Cu) = 5u;      /* GPIO_EMC_02 -> GPIO4_02 (PMIC_KILL) */
    REG32(0x401F820Cu) = 0x10B0u;
    GPIO_DR(GPIO4_BASE) &= ~(1u << 3);
    GPIO_GDIR(GPIO4_BASE) |= (1u << 3);
    delay_cycles(50000u);
    GPIO_DR(GPIO4_BASE) |= (1u << 2);
    GPIO_GDIR(GPIO4_BASE) |= (1u << 2);
    while (1) {
        __asm__ volatile ("nop");
    }
}

static void disable_watchdogs(void) {
    /* Clear WDE (bit 2) if enabled */
    WDOG1_WCR &= (uint16_t)~(1u << 2);
    WDOG2_WCR &= (uint16_t)~(1u << 2);
    /* Unlock and disable RTWDOG if needed */
    if (RTWDOG_CS & (1u << 7)) {
        RTWDOG_CNT = 0xD928C520u;
        RTWDOG_TOVAL = 0xFFFFu;
        RTWDOG_CS = (RTWDOG_CS & ~(1u << 7)) | (1u << 5);
    }
}

void Reset_Handler(void) {
    for (uint32_t *p = &__bss_start__; p < &__bss_end__; ++p) {
        *p = 0u;
    }

    disable_watchdogs();

    /* Enable peripheral clocks: LPUART3, ADC1, GPIO1-4, IOMUXC, XBARA1, FlexPWM4, and LPI2C1-4 */
    CCM_CCGR0 |= (3u << 12);
    CCM_CCGR1 |= (3u << 16) | (3u << 26) | (3u << 28) | (3u << 30);
    CCM_CCGR2 |= (3u << 6)  | (3u << 8) | (3u << 10) | (3u << 26);
    CCM_CCGR3 |= (3u << 12);
    CCM_CCGR4 |= (3u << 2)  | (3u << 22); /* IOMUXC + PWM4 */
    CCM_CCGR6 |= (3u << 24);
    __asm__ volatile ("dsb sy");

    DIAG_STATUS->magic      = 0x53544144u; /* "STAD" */
    DIAG_STATUS->version    = 6u;
    DIAG_STATUS->digprog    = REG32(0x400D8260u);
    DIAG_STATUS->ocotp_cfg5 = REG32(0x401F4460u);
    DIAG_STATUS->ticks      = 0u;

    haptics_gpio_safe_off();
    usb_cdc_init();
    bq2742x_wake_pulse(); /* Wake BQ2742X before BT HCD download covers ~500 ms settle time */

    uint32_t idle_psr[4] = { 0 };
    configure_button_gpios(idle_psr);

    uint32_t i2c_base = 0u;
    uint8_t lp_addr = 0u;
    int has_led = (probe_lp5562(&i2c_base, &lp_addr) == 0);
    int has_bt = bt_boot_and_advertise(has_led, i2c_base, lp_addr);

    uint16_t idle_sticks[6] = { 0 };
    adc1_init_sticks(idle_sticks);

    haptics_pwm_init();

    /* Ensure LPI2C1 is ready (without touching LPI2C3/sticks) and take initial battery reading */
    i2c_ensure_bus(0u);
    battery_poll_and_update(0);

    pro_input_t in = { 0, 0, 0, 2048u, 2048u, 2048u, 2048u };
    uint16_t stick_val[6] = {
        idle_sticks[0], idle_sticks[1], idle_sticks[2],
        idle_sticks[3], idle_sticks[4], idle_sticks[5]
    };
    uint32_t last_led_state = 0xFFu;
    uint8_t printed_banner = 0u;
    uint32_t repair_hold = 0u;
    uint8_t repair_fired = 0u;
    uint32_t poweroff_hold = 0u;

    while (1) {
        usb_cdc_poll();
        hall_probe_poll();
        if (has_bt) {
            bt_poll_uart(&in);
        }
        DIAG_STATUS->ticks += 1u;

        /* Haptics safety watchdog: auto-stop motors if host stops updating (~1.5 s) */
        if (g_rumble_wdog > 0u) {
            g_rumble_wdog--;
            if (g_rumble_wdog == 0u) {
                haptics_stop_all();
                if (g_usb_cfg && g_usb_dtr) {
                    usb_cdc_puts("RUMBLE WDOG STOP\r\n");
                }
            }
        }

        /* Periodic battery poll (~5.5 s interval @ ~12k ticks/s) */
        if ((DIAG_STATUS->ticks & 65535u) == 0u) {
            battery_poll_and_update(1);
        }

        if (g_usb_cfg && g_usb_dtr && !printed_banner) {
            printed_banner = 1u;
            usb_cdc_puts("\r\n=== STADIA DTCM CONSOLE READY ===\r\n");
            usb_cdc_puts("BT=");
            usb_cdc_put_u32((uint32_t)has_bt);
            usb_cdc_puts(" BD=");
            for (int i = 5; i >= 0; --i) {
                usb_cdc_put_hex8(g_bt.bd_addr[i]);
                if (i > 0) usb_cdc_puts(":");
            }
            usb_cdc_puts("\r\n");
            battery_poll_and_update(1);
        }
        if (!g_usb_dtr) {
            printed_banner = 0u;
        }
        uint32_t p1 = GPIO_PSR(GPIO1_BASE);
        uint32_t p2 = GPIO_PSR(GPIO2_BASE);
        uint32_t p3 = GPIO_PSR(GPIO3_BASE);
        uint32_t p4 = GPIO_PSR(GPIO4_BASE);
        DIAG_STATUS->gpio_psr[0] = p1;
        DIAG_STATUS->gpio_psr[1] = p2;
        DIAG_STATUS->gpio_psr[2] = p3;
        DIAG_STATUS->gpio_psr[3] = p4;

        /* Latch any pin once its pull-up RC filter settles high; press pulls low */
        idle_psr[0] |= p1;
        idle_psr[1] |= p2;
        idle_psr[2] |= p3;
        idle_psr[3] |= p4;

        uint32_t act1 = (idle_psr[0] & ~p1) & BTN_MASK_GPIO1;
        uint32_t act2 = (idle_psr[1] & ~p2) & BTN_MASK_GPIO2;
        uint32_t act3 = (idle_psr[2] & ~p3) & BTN_MASK_GPIO3;
        uint32_t act4 = (idle_psr[3] & ~p4) & BTN_MASK_GPIO4;

        /* Assistant (GPIO2_14) hold ~1.0 s -> disconnect & clear peer Link Key for re-pairing;
         * Stadia (GPIO2_11) + Assistant (GPIO2_14) hold ~2.5 s -> clean PMIC_KILL power-off. */
        int stadia_held = (act2 & (1u << 11)) != 0u;
        int asst_held = (act2 & (1u << 14)) != 0u;
        if (asst_held && stadia_held) {
            repair_hold = 0u;
            poweroff_hold++;
            if (poweroff_hold >= 30000u) {
                stadia_power_off(has_bt, has_led, i2c_base, lp_addr);
            }
        } else if (asst_held) {
            poweroff_hold = 0u;
            if (!repair_fired) {
                repair_hold++;
                if (repair_hold >= 12000u) {
                    repair_fired = 1u;
                    haptics_stop_all();
                    if (g_usb_cfg && g_usb_dtr) {
                        usb_cdc_puts("BT RE-PAIR (Assistant)\r\n");
                    }
                    if (has_bt) {
                        if (g_bt.connected) {
                            bt_link_key_clear_peer(g_bt.peer_bd_addr);
                            uint8_t disc[3] = {
                                (uint8_t)(g_bt.acl_handle & 0xFFu),
                                (uint8_t)((g_bt.acl_handle >> 8) & 0x0Fu),
                                0x13u
                            };
                            hci_send_cmd_nb(0x0406u, disc, 3u);
                        } else {
                            bt_link_key_clear_all();
                        }
                        uint8_t scan_both = 0x03u;
                        hci_send_cmd_nb(0x0C1Au, &scan_both, 1u);
                    }
                    if (has_led) {
                        lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, 0xFFu, 0x00u, 0x00u);
                        for (uint32_t w = 0u; w < 40u; ++w) {
                            lpuart3_drain_rx();
                            usb_cdc_poll();
                            delay_cycles(100000u);
                        }
                        last_led_state = 0xFFu;
                    }
                }
            }
        } else {
            repair_hold = 0u;
            repair_fired = 0u;
            poweroff_hold = 0u;
        }

        /* Sample one analog channel per loop to keep UART/USB polling fast */
        uint32_t ch_idx = DIAG_STATUS->ticks % 6u;
        stick_val[ch_idx] = adc_read_avg(ADC1_BASE, k_stick_channels[ch_idx]);
        if (has_bt) {
            lpuart3_drain_rx();
        }
        if (g_usb_cfg && g_usb_dtr && ((DIAG_STATUS->ticks & 2047u) == 0u)) {
            usb_cdc_puts("ADC IN8="); usb_cdc_put_u32(stick_val[4]);
            usb_cdc_puts(" IN13="); usb_cdc_put_u32(stick_val[5]);
            usb_cdc_puts(" LX="); usb_cdc_put_u32(stick_val[2]);
            usb_cdc_puts(" LY="); usb_cdc_put_u32(stick_val[3]);
            usb_cdc_puts(" RX="); usb_cdc_put_u32(stick_val[0]);
            usb_cdc_puts(" RY="); usb_cdc_put_u32(stick_val[1]);
            usb_cdc_puts(" BT="); usb_cdc_put_u32(g_bt.connected);
            usb_cdc_puts("/"); usb_cdc_put_u32(g_bt.l2cap_open[0]);
            usb_cdc_puts("/"); usb_cdc_put_u32(g_bt.hid_ready);
            usb_cdc_puts("\r\n");
        }

        /* Pack Switch Pro Controller inputs (with L2/R2 hysteresis) */
        static uint8_t zr_pressed = 0u;
        static uint8_t zl_pressed = 0u;
        if (!zr_pressed && (stick_val[4] + 350u < idle_sticks[4])) zr_pressed = 1u;
        else if (zr_pressed && (stick_val[4] + 250u >= idle_sticks[4])) zr_pressed = 0u;
        if (!zl_pressed && (stick_val[5] + 350u < idle_sticks[5])) zl_pressed = 1u;
        else if (zl_pressed && (stick_val[5] + 250u >= idle_sticks[5])) zl_pressed = 0u;

        in.btn_right = 0u;
        if (act2 & (1u << 3)) in.btn_right |= (1u << 0); /* Y */
        if (act2 & (1u << 2)) in.btn_right |= (1u << 1); /* X */
        if (act2 & (1u << 1)) in.btn_right |= (1u << 2); /* B */
        if (act2 & (1u << 0)) in.btn_right |= (1u << 3); /* A */
        if (act4 & (1u << 1)) in.btn_right |= (1u << 6); /* R (R1) */
        if (zr_pressed)       in.btn_right |= (1u << 7); /* ZR (R2) */

        in.btn_shared = 0u;
        if (act2 & (1u << 13)) in.btn_shared |= (1u << 0); /* Minus (Menu) */
        if (act2 & (1u << 12)) in.btn_shared |= (1u << 1); /* Plus (Options) */
        if (act1 & (1u << 2))  in.btn_shared |= (1u << 2); /* R3 */
        if (act1 & (1u << 0))  in.btn_shared |= (1u << 3); /* L3 */
        if (act2 & (1u << 11) && !asst_held) in.btn_shared |= (1u << 4); /* Home (Stadia) */
        if (act2 & (1u << 15)) in.btn_shared |= (1u << 5); /* Capture */

        in.btn_left = 0u;
        if (act3 & (1u << 1)) in.btn_left |= (1u << 0); /* Down */
        if (act3 & (1u << 0)) in.btn_left |= (1u << 1); /* Up */
        if (act3 & (1u << 3)) in.btn_left |= (1u << 2); /* Right */
        if (act3 & (1u << 2)) in.btn_left |= (1u << 3); /* Left */
        if (act4 & (1u << 0)) in.btn_left |= (1u << 6); /* L (L1) */
        if (zl_pressed)       in.btn_left |= (1u << 7); /* ZL (L2) */

        /* Center 12-bit stick values around idle_sticks */
        int32_t rx_s = 2048 + ((int32_t)stick_val[0] - (int32_t)idle_sticks[0]);
        int32_t ry_s = 2048 + ((int32_t)stick_val[1] - (int32_t)idle_sticks[1]);
        int32_t lx_s = 2048 + ((int32_t)stick_val[2] - (int32_t)idle_sticks[2]);
        int32_t ly_s = 2048 + ((int32_t)stick_val[3] - (int32_t)idle_sticks[3]);
        in.rx = (uint16_t)(rx_s < 0 ? 0 : (rx_s > 4095 ? 4095 : rx_s));
        in.ry = (uint16_t)(ry_s < 0 ? 0 : (ry_s > 4095 ? 4095 : ry_s));
        in.lx = (uint16_t)(lx_s < 0 ? 0 : (lx_s > 4095 ? 4095 : lx_s));
        in.ly = (uint16_t)(ly_s < 0 ? 0 : (ly_s > 4095 ? 4095 : ly_s));

        static uint32_t prev_btn_packed = 0u;
        uint32_t btn_packed = (uint32_t)in.btn_right |
                              ((uint32_t)in.btn_shared << 8) |
                              ((uint32_t)in.btn_left << 16);
        if (has_bt && g_bt.hid_ready) {
            if (g_bt.report_mode == 0x30u) {
                if ((DIAG_STATUS->ticks & 255u) == 0u) {
                    hid_send_input_report(&in);
                }
            } else if (btn_packed != prev_btn_packed) {
                /* 0x3F simple mode: only emit on button change (no unsolicited flood on pairing) */
                hid_send_input_report(&in);
            }
        }
        prev_btn_packed = btn_packed;

        if (has_led) {
            uint8_t on = ((DIAG_STATUS->ticks >> 12) & 1u) ? 1u : 0u;
            uint32_t st = g_bt.hid_ready ? 4u :
                          (g_bt.l2cap_open[0] ? 3u :
                          (g_bt.connected ? 2u :
                          (has_bt ? (on ? 1u : 0u) : (on ? 5u : 6u))));
            if (st != last_led_state) {
                last_led_state = st;
                if (st == 4u) {
                    /* Solid Orange + White when HID Interrupt is ready (LP5562 ch G = Orange LED on Stadia PCB) */
                    lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, 0x80u, 0x00u, 0xFFu);
                } else if (st == 3u) {
                    /* Solid Orange when SDP channel is open (LP5562 ch G = Orange LED on Stadia PCB) */
                    lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, 0xFFu, 0x00u, 0x00u);
                } else if (st == 2u) {
                    /* Solid White when ACL is connected */
                    lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, 0x00u, 0x00u, 0xFFu);
                } else if (st == 1u) {
                    lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, 0x00u, 0x00u, 0xFFu);
                } else if (st == 0u) {
                    lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, 0x00u, 0x00u, 0x00u);
                } else if (st == 5u) {
                    lp5562_set_rgbw(i2c_base, lp_addr, 0xFFu, 0x00u, 0x00u, 0x00u);
                } else {
                    lp5562_set_rgbw(i2c_base, lp_addr, 0x00u, 0xFFu, 0x00u, 0x00u);
                }
            }
        }
        delay_cycles(5000u);
    }
}
