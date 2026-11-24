#pragma once
#include <stdint.h>

/* i.MX RT1060 USB1 (ChipIdea EHCI Device) & USBPHY1 */
#define USB1_BASE        0x402E0000u
#define USBPHY1_BASE     0x400D9000u

#define USB_USBCMD       (*(volatile uint32_t *)(USB1_BASE + 0x140u))
#define USB_USBSTS       (*(volatile uint32_t *)(USB1_BASE + 0x144u))
#define USB_DEVICEADDR   (*(volatile uint32_t *)(USB1_BASE + 0x154u))
#define USB_EPLISTADDR   (*(volatile uint32_t *)(USB1_BASE + 0x158u))
#define USB_PORTSC1      (*(volatile uint32_t *)(USB1_BASE + 0x184u))
#define USB_USBMODE      (*(volatile uint32_t *)(USB1_BASE + 0x1A8u))
#define USB_EPSETUPSR    (*(volatile uint32_t *)(USB1_BASE + 0x1ACu))
#define USB_EPPRIME      (*(volatile uint32_t *)(USB1_BASE + 0x1B0u))
#define USB_EPFLUSH      (*(volatile uint32_t *)(USB1_BASE + 0x1B4u))
#define USB_EPSTAT       (*(volatile uint32_t *)(USB1_BASE + 0x1B8u))
#define USB_EPCOMPLETE   (*(volatile uint32_t *)(USB1_BASE + 0x1BCu))
#define USB_EPCTRL(n)    (*(volatile uint32_t *)(USB1_BASE + 0x1C0u + ((uint32_t)(n) * 4u)))

#define USBPHY_PWD       (*(volatile uint32_t *)(USBPHY1_BASE + 0x00u))
#define USBPHY_CTRL      (*(volatile uint32_t *)(USBPHY1_BASE + 0x30u))

static inline void usb_dsb(void) {
    __asm__ volatile("dsb sy" ::: "memory");
}

/* ChipIdea Queue Head (64 bytes) & Transfer Descriptor (32 bytes) in OCRAM (0x20200000) */
typedef struct __attribute__((packed, aligned(64))) {
    volatile uint32_t cap;
    volatile uint32_t curr_dtd;
    volatile uint32_t next_dtd;
    volatile uint32_t token;
    volatile uint32_t buf[5];
    volatile uint32_t reserved;
    volatile uint32_t setup[2];
    volatile uint32_t pad[4];
} usb_qhd_t;

typedef struct __attribute__((packed, aligned(32))) {
    volatile uint32_t next;
    volatile uint32_t token;
    volatile uint32_t buf[5];
    volatile uint32_t pad;
} usb_dtd_t;

/* OCRAM DMA workspace @ 0x20200000 (2048-byte aligned for ENDPOINTLISTADDR) */
typedef struct {
    usb_qhd_t qhd[8];      /* EP0 OUT, EP0 IN, EP1 OUT, EP1 IN, EP2 OUT, EP2 IN, EP3 OUT, EP3 IN (512B) */
    usb_dtd_t dtd[8];      /* One dTD per endpoint direction (256B) */
    uint8_t ep0_buf[128];
    uint8_t bulk_rx[64];
    uint8_t bulk_tx[64];
    uint8_t line_coding[7];
} usb_ocram_t;

#define USB_OCRAM ((usb_ocram_t *)0x20200000u)

static volatile uint8_t g_usb_cfg = 0u;
static volatile uint8_t g_usb_dtr = 0u;
static uint8_t g_cdc_rx_ring[256];
static volatile uint32_t g_cdc_rx_head = 0u;
static volatile uint32_t g_cdc_rx_tail = 0u;

static const uint8_t k_dev_desc[18] = {
    18u, 0x01u, 0x00u, 0x02u, /* USB 2.0 */
    0x02u, 0x00u, 0x00u,      /* CDC */
    64u,                      /* EP0 MPS = 64 */
    0xC9u, 0x1Fu,             /* VID 0x1FC9 */
    0x94u, 0x00u,             /* PID 0x0094 */
    0x00u, 0x01u,             /* bcdDevice 1.00 */
    1u, 2u, 3u,               /* Strings */
    1u                        /* 1 config */
};

static const uint8_t k_cfg_desc[67] = {
    /* Configuration Descriptor */
    9u, 0x02u, 67u, 0x00u, 2u, 1u, 0u, 0x80u, 50u,
    /* Interface 0: CDC Communication */
    9u, 0x04u, 0u, 0u, 1u, 0x02u, 0x02u, 0x01u, 0u,
    /* Header Functional */
    5u, 0x24u, 0x00u, 0x10u, 0x01u,
    /* Call Management */
    5u, 0x24u, 0x01u, 0x00u, 0x01u,
    /* ACM */
    4u, 0x24u, 0x02u, 0x02u,
    /* Union */
    5u, 0x24u, 0x06u, 0u, 1u,
    /* EP1 IN (Interrupt, 16B) */
    7u, 0x05u, 0x81u, 0x03u, 16u, 0x00u, 16u,
    /* Interface 1: CDC Data */
    9u, 0x04u, 1u, 0u, 2u, 0x0Au, 0x00u, 0x00u, 0u,
    /* EP2 OUT (Bulk, 64B) */
    7u, 0x05u, 0x02u, 0x02u, 64u, 0x00u, 0u,
    /* EP2 IN (Bulk, 64B) */
    7u, 0x05u, 0x82u, 0x02u, 64u, 0x00u, 0u
};

static const uint8_t k_str0[4] = { 4u, 0x03u, 0x09u, 0x04u };
static const uint8_t k_str1[14] = { 14u, 0x03u, 'S',0,'t',0,'a',0,'d',0,'i',0,'a',0 };
static const uint8_t k_str2[22] = { 22u, 0x03u, 'S',0,'t',0,'a',0,'d',0,'i',0,'a',0,' ',0,'C',0,'D',0,'C',0 };
static const uint8_t k_str3[10] = { 10u, 0x03u, '0',0,'0',0,'0',0,'1',0 };

static void usb_start_dtd(uint32_t idx, const void *buf, uint32_t len) {
    usb_dtd_t *d = &USB_OCRAM->dtd[idx];
    usb_qhd_t *q = &USB_OCRAM->qhd[idx];
    uint32_t addr = (uint32_t)buf;
    d->next = 1u; /* Terminate */
    d->token = (len << 16) | (1u << 15) | (1u << 7); /* IOC | Active */
    d->buf[0] = addr;
    d->buf[1] = (addr + 0x1000u) & ~0xFFFu;
    d->buf[2] = 0u;
    d->buf[3] = 0u;
    d->buf[4] = 0u;
    q->next_dtd = (uint32_t)d;
    q->token &= ~0xFFu;
    usb_dsb();
    uint32_t ep = idx >> 1;
    uint32_t dir = idx & 1u;
    USB_EPPRIME = 1u << (ep + (dir ? 16u : 0u));
}

static void usb_ep0_tx(const void *src, uint32_t len, uint32_t wlength) {
    if (len > wlength) {
        len = wlength;
    }
    if (len > sizeof(USB_OCRAM->ep0_buf)) {
        len = sizeof(USB_OCRAM->ep0_buf);
    }
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0u; i < len; ++i) {
        USB_OCRAM->ep0_buf[i] = s[i];
    }
    usb_start_dtd(1u, USB_OCRAM->ep0_buf, len);
    if (len > 0u) {
        usb_start_dtd(0u, USB_OCRAM->ep0_buf, 0u); /* Status OUT */
    }
}

static void usb_ep0_ack(void) {
    usb_start_dtd(1u, USB_OCRAM->ep0_buf, 0u);
}

static void usb_cdc_init(void) {
    g_usb_cfg = 0u;
    g_usb_dtr = 0u;
    g_cdc_rx_head = 0u;
    g_cdc_rx_tail = 0u;

    /* Disconnect and reset USB1 controller cleanly (BootROM already enabled PLL3 + PHY) */
    USB_USBCMD &= ~1u;
    for (volatile uint32_t d = 0u; d < 2000000u; ++d) {}
    USB_USBCMD |= (1u << 1);
    while (USB_USBCMD & (1u << 1)) {}

    USBPHY_PWD = 0u;
    USB_USBMODE = 0x02u | (1u << 3); /* Device mode + SLOM */

    uint8_t *p = (uint8_t *)USB_OCRAM;
    for (uint32_t i = 0u; i < sizeof(usb_ocram_t); ++i) {
        p[i] = 0u;
    }
    /* Default 115200 8N1 line coding */
    USB_OCRAM->line_coding[0] = 0x00u;
    USB_OCRAM->line_coding[1] = 0xC2u;
    USB_OCRAM->line_coding[2] = 0x01u;
    USB_OCRAM->line_coding[3] = 0x00u;
    USB_OCRAM->line_coding[6] = 8u;

    /* EP0 OUT (idx 0) and EP0 IN (idx 1): MPS=64, IOS=1 */
    USB_OCRAM->qhd[0].cap = (64u << 16) | (1u << 15);
    USB_OCRAM->qhd[0].next_dtd = 1u;
    USB_OCRAM->qhd[1].cap = (64u << 16) | (1u << 15);
    USB_OCRAM->qhd[1].next_dtd = 1u;
    /* EP1 IN (idx 3): Interrupt MPS=16 */
    USB_OCRAM->qhd[3].cap = (16u << 16);
    USB_OCRAM->qhd[3].next_dtd = 1u;
    /* EP2 OUT (idx 4) & EP2 IN (idx 5): Bulk MPS=64, ZLT=1 */
    USB_OCRAM->qhd[4].cap = (64u << 16) | (1u << 29);
    USB_OCRAM->qhd[4].next_dtd = 1u;
    USB_OCRAM->qhd[5].cap = (64u << 16) | (1u << 29);
    USB_OCRAM->qhd[5].next_dtd = 1u;

    usb_dsb();
    USB_EPLISTADDR = (uint32_t)USB_OCRAM->qhd;
    USB_USBSTS = 0xFFFFFFFFu;
    USB_USBCMD = 1u; /* Run / Attach */
}

static void usb_handle_setup(void) {
    uint32_t s0, s1;
    do {
        USB_USBCMD |= (1u << 13); /* SUTW */
        s0 = USB_OCRAM->qhd[0].setup[0];
        s1 = USB_OCRAM->qhd[0].setup[1];
    } while ((USB_USBCMD & (1u << 13)) == 0u);
    USB_USBCMD &= ~(1u << 13);
    USB_EPSETUPSR = 1u;

    uint8_t bmReq = (uint8_t)(s0 & 0xFFu);
    uint8_t bReq  = (uint8_t)((s0 >> 8) & 0xFFu);
    uint16_t wVal = (uint16_t)(s0 >> 16);
    uint16_t wLen = (uint16_t)(s1 >> 16);

    if ((bmReq & 0x60u) == 0x00u) {
        /* Standard requests */
        if (bReq == 0x05u) {
            /* SET_ADDRESS (USBADRA bit 24 auto-advances after status IN) */
            USB_DEVICEADDR = ((uint32_t)(wVal & 0x7Fu) << 25) | (1u << 24);
            usb_ep0_ack();
        } else if (bReq == 0x06u) {
            /* GET_DESCRIPTOR */
            uint8_t dtype = (uint8_t)(wVal >> 8);
            uint8_t didx  = (uint8_t)(wVal & 0xFFu);
            if (dtype == 0x01u) {
                usb_ep0_tx(k_dev_desc, sizeof(k_dev_desc), wLen);
            } else if (dtype == 0x02u) {
                usb_ep0_tx(k_cfg_desc, sizeof(k_cfg_desc), wLen);
            } else if (dtype == 0x03u) {
                if (didx == 0u) usb_ep0_tx(k_str0, sizeof(k_str0), wLen);
                else if (didx == 1u) usb_ep0_tx(k_str1, sizeof(k_str1), wLen);
                else if (didx == 2u) usb_ep0_tx(k_str2, sizeof(k_str2), wLen);
                else usb_ep0_tx(k_str3, sizeof(k_str3), wLen);
            } else {
                USB_EPCTRL(0) |= (1u << 16) | (1u << 0); /* STALL */
            }
        } else if (bReq == 0x09u) {
            /* SET_CONFIGURATION */
            g_usb_cfg = (uint8_t)(wVal & 0xFFu);
            USB_EPCTRL(1) = (3u << 18) | (1u << 23) | (1u << 22); /* EP1 IN Interrupt */
            USB_EPCTRL(2) = (2u << 2)  | (1u << 7)  | (1u << 6) |
                            (2u << 18) | (1u << 23) | (1u << 22); /* EP2 OUT+IN Bulk */
            usb_start_dtd(4u, USB_OCRAM->bulk_rx, 64u); /* Arm EP2 OUT */
            usb_ep0_ack();
        } else if (bReq == 0x08u) {
            usb_ep0_tx((const void *)&g_usb_cfg, 1u, wLen);
        } else if (bReq == 0x00u) {
            uint8_t st[2] = { 0u, 0u };
            usb_ep0_tx(st, 2u, wLen);
        } else {
            usb_ep0_ack();
        }
    } else {
        /* CDC Class requests */
        if (bReq == 0x20u) {
            /* SET_LINE_CODING (7 bytes OUT) */
            usb_start_dtd(0u, USB_OCRAM->line_coding, 7u);
            usb_ep0_ack();
        } else if (bReq == 0x21u) {
            /* GET_LINE_CODING */
            usb_ep0_tx(USB_OCRAM->line_coding, 7u, wLen);
        } else if (bReq == 0x22u) {
            /* SET_CONTROL_LINE_STATE (DTR = bit 0) */
            g_usb_dtr = (uint8_t)(wVal & 1u);
            usb_ep0_ack();
        } else {
            usb_ep0_ack();
        }
    }
}

static uint8_t g_cdc_tx_ring[1024];
static uint32_t g_cdc_tx_head = 0u;
static uint32_t g_cdc_tx_tail = 0u;
static uint8_t g_cdc_tx_zlp = 0u;

static void usb_cdc_tx_kick(void) {
    if (!g_usb_cfg || !g_usb_dtr) {
        g_cdc_tx_head = 0u;
        g_cdc_tx_tail = 0u;
        g_cdc_tx_zlp = 0u;
        return;
    }
    if ((USB_EPSTAT & (1u << 18)) != 0u ||
        (USB_OCRAM->dtd[5].token & (1u << 7)) != 0u) {
        return;
    }
    uint32_t n = 0u;
    while (n < 64u && g_cdc_tx_tail != g_cdc_tx_head) {
        USB_OCRAM->bulk_tx[n++] = g_cdc_tx_ring[g_cdc_tx_tail];
        g_cdc_tx_tail = (g_cdc_tx_tail + 1u) & 1023u;
    }
    if (n > 0u) {
        g_cdc_tx_zlp = (n == 64u) ? 1u : 0u;
        usb_start_dtd(5u, USB_OCRAM->bulk_tx, n);
    } else if (g_cdc_tx_zlp) {
        g_cdc_tx_zlp = 0u;
        usb_start_dtd(5u, USB_OCRAM->bulk_tx, 0u);
    }
}

static void usb_cdc_poll(void) {
    uint32_t sts = USB_USBSTS;
    if (sts & (1u << 6)) {
        /* USB Bus Reset */
        USB_USBSTS = (1u << 6);
        USB_EPSETUPSR = USB_EPSETUPSR;
        USB_EPCOMPLETE = USB_EPCOMPLETE;
        USB_EPFLUSH = 0xFFFFFFFFu;
        while (USB_EPFLUSH) {}
        USB_DEVICEADDR = 0u;
        g_usb_cfg = 0u;
        g_usb_dtr = 0u;
        g_cdc_tx_head = 0u;
        g_cdc_tx_tail = 0u;
        g_cdc_tx_zlp = 0u;
    }
    if (sts & 1u) {
        USB_USBSTS = 1u;
    }
    if (USB_EPSETUPSR & 1u) {
        usb_handle_setup();
    }
    uint32_t comp = USB_EPCOMPLETE;
    if (comp) {
        USB_EPCOMPLETE = comp;
        if (comp & (1u << 2)) {
            /* EP2 OUT Bulk RX complete */
            uint32_t rem = (USB_OCRAM->dtd[4].token >> 16) & 0x7FFFu;
            uint32_t got = (rem <= 64u) ? (64u - rem) : 0u;
            for (uint32_t i = 0u; i < got; ++i) {
                uint32_t next = (g_cdc_rx_head + 1u) & 255u;
                if (next != g_cdc_rx_tail) {
                    g_cdc_rx_ring[g_cdc_rx_head] = USB_OCRAM->bulk_rx[i];
                    g_cdc_rx_head = next;
                }
            }
            usb_start_dtd(4u, USB_OCRAM->bulk_rx, 64u);
        }
    }
    usb_cdc_tx_kick();
}

static int usb_cdc_getc(uint8_t *out) {
    if (g_cdc_rx_tail == g_cdc_rx_head) {
        return -1;
    }
    *out = g_cdc_rx_ring[g_cdc_rx_tail];
    g_cdc_rx_tail = (g_cdc_rx_tail + 1u) & 255u;
    return 0;
}

static void usb_cdc_write(const uint8_t *data, uint32_t len) {
    if (!g_usb_cfg || !g_usb_dtr) {
        g_cdc_tx_head = 0u;
        g_cdc_tx_tail = 0u;
        g_cdc_tx_zlp = 0u;
        return;
    }
    for (uint32_t i = 0u; i < len; ++i) {
        uint32_t next = (g_cdc_tx_head + 1u) & 1023u;
        if (next == g_cdc_tx_tail) {
            break; /* Drop excess rather than stalling main loop / BT UART */
        }
        g_cdc_tx_ring[g_cdc_tx_head] = data[i];
        g_cdc_tx_head = next;
    }
    usb_cdc_tx_kick();
}

static void usb_cdc_puts(const char *s) {
    uint32_t len = 0u;
    while (s[len]) ++len;
    usb_cdc_write((const uint8_t *)s, len);
}

static void usb_cdc_put_u32(uint32_t v) {
    char buf[12];
    int i = 0;
    if (v == 0u) {
        buf[i++] = '0';
    } else {
        char tmp[12];
        int t = 0;
        while (v > 0u) {
            tmp[t++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
        while (t > 0) {
            buf[i++] = tmp[--t];
        }
    }
    usb_cdc_write((const uint8_t *)buf, (uint32_t)i);
}

static void usb_cdc_put_hex8(uint8_t v) {
    static const char hx[] = "0123456789ABCDEF";
    uint8_t b[2] = { (uint8_t)hx[v >> 4], (uint8_t)hx[v & 0x0Fu] };
    usb_cdc_write(b, 2u);
}
