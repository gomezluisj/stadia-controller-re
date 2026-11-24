#pragma once
#include <stdint.h>

/* Callback provided by main.c to transmit an HCI packet over LPUART3 */
void bt_uart_write(const uint8_t *data, uint32_t len);

/* Live controller input state populated by main.c */
typedef struct {
    uint8_t btn_right;   /* bit0=Y, 1=X, 2=B, 3=A, 6=R, 7=ZR */
    uint8_t btn_shared;  /* bit0=Minus, 1=Plus, 2=R3, 3=L3, 4=Home, 5=Capture */
    uint8_t btn_left;    /* bit0=Down, 1=Up, 2=Right, 3=Left, 6=L, 7=ZL */
    uint16_t lx;         /* 12-bit 0..4095, center 2048 */
    uint16_t ly;         /* 12-bit 0..4095, center 2048 */
    uint16_t rx;         /* 12-bit 0..4095, center 2048 */
    uint16_t ry;         /* 12-bit 0..4095, center 2048 */
} pro_input_t;

typedef struct {
    uint16_t acl_handle;
    uint8_t bd_addr[6];
    uint8_t connected;
    uint8_t hid_ready;
    uint8_t report_mode; /* 0x3F default, 0x30 full */
    uint8_t timer;
    uint8_t player_leds;
    uint8_t acl_in_flight;

    /* L2CAP channel tracking: 0=SDP(0x0001), 1=HID_CTRL(0x0011), 2=HID_INTR(0x0013) */
    uint16_t l2cap_host_cid[3];
    uint8_t l2cap_open[3];
    uint8_t l2cap_cfg_rx[3];
    uint8_t l2cap_cfg_tx[3];
    uint8_t l2cap_sig_id;

    /* HCI ACL L2CAP reassembly state */
    uint16_t reasm_expect;
    uint16_t reasm_len;
    uint16_t reasm_cid;
} bt_hid_state_t;

static bt_hid_state_t g_bt;
static uint8_t g_acl_reasm[700];

static void bt_hid_init_state(const uint8_t bd_addr[6]) {
    g_bt.acl_handle = 0u;
    for (uint32_t i = 0u; i < 6u; ++i) {
        g_bt.bd_addr[i] = bd_addr[i];
    }
    g_bt.connected = 0u;
    g_bt.hid_ready = 0u;
    g_bt.report_mode = 0x3Fu;
    g_bt.timer = 0u;
    g_bt.player_leds = 0u;
    g_bt.acl_in_flight = 0u;
    for (uint32_t i = 0u; i < 3u; ++i) {
        g_bt.l2cap_host_cid[i] = 0u;
        g_bt.l2cap_open[i] = 0u;
        g_bt.l2cap_cfg_rx[i] = 0u;
        g_bt.l2cap_cfg_tx[i] = 0u;
    }
    g_bt.l2cap_sig_id = 1u;
    g_bt.reasm_expect = 0u;
    g_bt.reasm_len = 0u;
    g_bt.reasm_cid = 0u;
}

static void bt_handle_num_completed_packets(const uint8_t *buf, uint32_t len) {
    if (len < 3u) {
        return;
    }
    uint8_t n = buf[2];
    for (uint8_t i = 0u; i < n && (3u + (uint32_t)i * 4u + 3u) < len; ++i) {
        uint16_t h = (uint16_t)buf[3u + i * 4u] | ((uint16_t)buf[4u + i * 4u] << 8);
        if (h != g_bt.acl_handle) {
            continue;
        }
        uint16_t done = (uint16_t)buf[5u + i * 4u] | ((uint16_t)buf[6u + i * 4u] << 8);
        if (done >= g_bt.acl_in_flight) {
            g_bt.acl_in_flight = 0u;
        } else {
            g_bt.acl_in_flight = (uint8_t)(g_bt.acl_in_flight - (uint8_t)done);
        }
    }
}

static void hci_send_acl(uint16_t cid, const uint8_t *payload, uint16_t plen) {
    if (!g_bt.connected) {
        return;
    }
    if (g_bt.acl_in_flight < 255u) {
        g_bt.acl_in_flight++;
    }
    uint8_t hdr[9];
    uint16_t acl_len = (uint16_t)(plen + 4u);
    hdr[0] = 0x02u; /* HCI ACL Data */
    hdr[1] = (uint8_t)(g_bt.acl_handle & 0xFFu);
    hdr[2] = (uint8_t)(((g_bt.acl_handle >> 8) & 0x0Fu) | 0x20u); /* PB=10b */
    hdr[3] = (uint8_t)(acl_len & 0xFFu);
    hdr[4] = (uint8_t)(acl_len >> 8);
    hdr[5] = (uint8_t)(plen & 0xFFu);
    hdr[6] = (uint8_t)(plen >> 8);
    hdr[7] = (uint8_t)(cid & 0xFFu);
    hdr[8] = (uint8_t)(cid >> 8);
    bt_uart_write(hdr, 9u);
    if (plen > 0u) {
        bt_uart_write(payload, plen);
    }
}

static void l2cap_send_sig(uint8_t code, uint8_t id, const uint8_t *data, uint16_t dlen) {
    uint8_t buf[32];
    if ((uint32_t)dlen + 4u > sizeof(buf)) {
        return;
    }
    buf[0] = code;
    buf[1] = id;
    buf[2] = (uint8_t)(dlen & 0xFFu);
    buf[3] = (uint8_t)(dlen >> 8);
    for (uint16_t i = 0u; i < dlen; ++i) {
        buf[4u + i] = data[i];
    }
    hci_send_acl(0x0001u, buf, (uint16_t)(dlen + 4u));
}

static void l2cap_send_config_req(uint16_t dcid) {
    uint8_t cfg[8];
    cfg[0] = (uint8_t)(dcid & 0xFFu);
    cfg[1] = (uint8_t)(dcid >> 8);
    cfg[2] = 0x00u;
    cfg[3] = 0x00u;
    /* Option: MTU (type=0x01, len=0x02, val=672 = 0x02A0) */
    cfg[4] = 0x01u;
    cfg[5] = 0x02u;
    cfg[6] = 0xA0u;
    cfg[7] = 0x02u;
    l2cap_send_sig(0x04u, g_bt.l2cap_sig_id++, cfg, 8u);
}

/* Standard Switch Pro Controller HID Report Descriptor (170 bytes) */
static const uint8_t k_switch_hid_desc[] = {
    0x05u, 0x01u, 0x09u, 0x05u, 0xA1u, 0x01u,
    0x06u, 0x01u, 0xFFu,
    0x85u, 0x21u, 0x09u, 0x21u, 0x75u, 0x08u, 0x95u, 0x30u, 0x81u, 0x02u,
    0x85u, 0x30u, 0x09u, 0x30u, 0x75u, 0x08u, 0x95u, 0x30u, 0x81u, 0x02u,
    0x85u, 0x31u, 0x09u, 0x31u, 0x75u, 0x08u, 0x96u, 0x69u, 0x01u, 0x81u, 0x02u,
    0x85u, 0x32u, 0x09u, 0x32u, 0x75u, 0x08u, 0x96u, 0x69u, 0x01u, 0x81u, 0x02u,
    0x85u, 0x33u, 0x09u, 0x33u, 0x75u, 0x08u, 0x96u, 0x69u, 0x01u, 0x81u, 0x02u,
    0x85u, 0x3Fu, 0x05u, 0x09u, 0x19u, 0x01u, 0x29u, 0x10u, 0x15u, 0x00u, 0x25u, 0x01u,
    0x75u, 0x01u, 0x95u, 0x10u, 0x81u, 0x02u,
    0x05u, 0x01u, 0x09u, 0x39u, 0x15u, 0x00u, 0x25u, 0x07u, 0x75u, 0x04u, 0x95u, 0x01u,
    0x81u, 0x42u, 0x05u, 0x09u, 0x75u, 0x04u, 0x95u, 0x01u, 0x81u, 0x01u,
    0x05u, 0x01u, 0x09u, 0x30u, 0x09u, 0x31u, 0x09u, 0x33u, 0x09u, 0x34u, 0x16u, 0x00u, 0x00u,
    0x27u, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x75u, 0x10u, 0x95u, 0x04u, 0x81u, 0x02u,
    0x06u, 0x00u, 0xFFu, 0x85u, 0x01u, 0x09u, 0x01u, 0x75u, 0x08u, 0x95u, 0x30u, 0x91u, 0x02u,
    0x85u, 0x10u, 0x09u, 0x10u, 0x75u, 0x08u, 0x95u, 0x30u, 0x91u, 0x02u,
    0x85u, 0x11u, 0x09u, 0x11u, 0x75u, 0x08u, 0x95u, 0x30u, 0x91u, 0x02u,
    0x85u, 0x12u, 0x09u, 0x12u, 0x75u, 0x08u, 0x95u, 0x30u, 0x91u, 0x02u,
    0xC0u
};

/* Build SDP HID record (handle 0x00010000) into dst, returns byte length */
static uint16_t sdp_build_hid_record(uint8_t *dst) {
    uint16_t p = 0u;
    /* Reserve 2 bytes for outer DataElementSequence (0x35, len) -> actually 0x36 (16-bit len) */
    dst[p++] = 0x36u;
    uint16_t seq_len_pos = p;
    p += 2u;

    /* 0x0000: ServiceRecordHandle = 0x00010000 */
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x00u;
    dst[p++] = 0x0Au; dst[p++] = 0x00u; dst[p++] = 0x01u; dst[p++] = 0x00u; dst[p++] = 0x00u;

    /* 0x0001: ServiceClassIDList = { UUID16(0x1124) } */
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x01u;
    dst[p++] = 0x35u; dst[p++] = 0x03u;
    dst[p++] = 0x19u; dst[p++] = 0x11u; dst[p++] = 0x24u;

    /* 0x0004: ProtocolDescriptorList = { {L2CAP, 0x0011}, {HIDP} } */
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x04u;
    dst[p++] = 0x35u; dst[p++] = 0x0Du;
    dst[p++] = 0x35u; dst[p++] = 0x06u; dst[p++] = 0x19u; dst[p++] = 0x01u; dst[p++] = 0x00u;
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x11u;
    dst[p++] = 0x35u; dst[p++] = 0x03u; dst[p++] = 0x19u; dst[p++] = 0x00u; dst[p++] = 0x11u;

    /* 0x000D: AdditionalProtocolDescriptorLists = { { {L2CAP, 0x0013}, {HIDP} } } */
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x0Du;
    dst[p++] = 0x35u; dst[p++] = 0x0Fu;
    dst[p++] = 0x35u; dst[p++] = 0x0Du;
    dst[p++] = 0x35u; dst[p++] = 0x06u; dst[p++] = 0x19u; dst[p++] = 0x01u; dst[p++] = 0x00u;
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x13u;
    dst[p++] = 0x35u; dst[p++] = 0x03u; dst[p++] = 0x19u; dst[p++] = 0x00u; dst[p++] = 0x11u;

    /* 0x0100: ServiceName = "Wireless Gamepad" (16 bytes) */
    dst[p++] = 0x09u; dst[p++] = 0x01u; dst[p++] = 0x00u;
    dst[p++] = 0x25u; dst[p++] = 16u;
    static const char sname[] = "Wireless Gamepad";
    for (uint32_t i = 0u; i < 16u; ++i) {
        dst[p++] = (uint8_t)sname[i];
    }

    /* 0x0200: HIDDeviceReleaseNumber = 0x0100 */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x00u;
    dst[p++] = 0x09u; dst[p++] = 0x01u; dst[p++] = 0x00u;

    /* 0x0201: HIDParserVersion = 0x0111 */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x01u;
    dst[p++] = 0x09u; dst[p++] = 0x01u; dst[p++] = 0x11u;

    /* 0x0202: HIDDeviceSubclass = 0x08 (Gamepad) */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x02u;
    dst[p++] = 0x08u; dst[p++] = 0x08u;

    /* 0x0203: HIDCountryCode = 0x21 */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x03u;
    dst[p++] = 0x08u; dst[p++] = 0x21u;

    /* 0x0204: HIDVirtualCable = true */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x04u;
    dst[p++] = 0x28u; dst[p++] = 0x01u;

    /* 0x0205: HIDReconnectInitiate = true */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x05u;
    dst[p++] = 0x28u; dst[p++] = 0x01u;

    /* 0x0206: HIDDescriptorList = { { 0x22 (Report), str(k_switch_hid_desc) } } */
    uint16_t dlen = (uint16_t)sizeof(k_switch_hid_desc);
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x06u;
    dst[p++] = 0x35u; dst[p++] = (uint8_t)(dlen + 6u);
    dst[p++] = 0x35u; dst[p++] = (uint8_t)(dlen + 4u);
    dst[p++] = 0x08u; dst[p++] = 0x22u;
    dst[p++] = 0x25u; dst[p++] = (uint8_t)dlen;
    for (uint16_t i = 0u; i < dlen; ++i) {
        dst[p++] = k_switch_hid_desc[i];
    }

    /* 0x020B: HIDProfileVersion = 0x0100 */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x0Bu;
    dst[p++] = 0x09u; dst[p++] = 0x01u; dst[p++] = 0x00u;

    /* 0x020E: HIDNormallyConnectable = true */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x0Eu;
    dst[p++] = 0x28u; dst[p++] = 0x01u;

    uint16_t inner = (uint16_t)(p - 3u);
    dst[seq_len_pos] = (uint8_t)(inner >> 8);
    dst[seq_len_pos + 1u] = (uint8_t)(inner & 0xFFu);
    return p;
}

/* Build SDP PnP Information record (handle 0x00010001, VID=0x057E, PID=0x2009) */
static uint16_t sdp_build_pnp_record(uint8_t *dst) {
    uint16_t p = 0u;
    dst[p++] = 0x35u;
    uint16_t len_pos = p++;

    /* 0x0000: ServiceRecordHandle = 0x00010001 */
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x00u;
    dst[p++] = 0x0Au; dst[p++] = 0x00u; dst[p++] = 0x01u; dst[p++] = 0x00u; dst[p++] = 0x01u;

    /* 0x0001: ServiceClassIDList = { UUID16(0x1200) } */
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x01u;
    dst[p++] = 0x35u; dst[p++] = 0x03u;
    dst[p++] = 0x19u; dst[p++] = 0x12u; dst[p++] = 0x00u;

    /* 0x0200: SpecificationID = 0x0103 */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x00u;
    dst[p++] = 0x09u; dst[p++] = 0x01u; dst[p++] = 0x03u;

    /* 0x0201: VendorID = 0x057E (Nintendo) */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x01u;
    dst[p++] = 0x09u; dst[p++] = 0x05u; dst[p++] = 0x7Eu;

    /* 0x0202: ProductID = 0x2009 (Pro Controller) */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x02u;
    dst[p++] = 0x09u; dst[p++] = 0x20u; dst[p++] = 0x09u;

    /* 0x0203: Version = 0x0100 */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x03u;
    dst[p++] = 0x09u; dst[p++] = 0x01u; dst[p++] = 0x00u;

    /* 0x0204: PrimaryRecord = true */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x04u;
    dst[p++] = 0x28u; dst[p++] = 0x01u;

    /* 0x0205: VendorIDSource = 0x0002 (USB-IF) */
    dst[p++] = 0x09u; dst[p++] = 0x02u; dst[p++] = 0x05u;
    dst[p++] = 0x09u; dst[p++] = 0x00u; dst[p++] = 0x02u;

    dst[len_pos] = (uint8_t)(p - 2u);
    return p;
}

static int buf_contains_u16_be(const uint8_t *b, uint16_t len, uint16_t val) {
    uint8_t hi = (uint8_t)(val >> 8);
    uint8_t lo = (uint8_t)(val & 0xFFu);
    for (uint16_t i = 0u; i + 1u < len; ++i) {
        if (b[i] == hi && b[i + 1u] == lo) {
            return 1;
        }
    }
    return 0;
}

static uint16_t sdp_de_size(const uint8_t *p, uint16_t avail) {
    if (avail == 0u) {
        return 0u;
    }
    uint8_t size_desc = p[0] & 0x07u;
    if ((p[0] & 0xF8u) == 0u) {
        return 1u; /* Nil */
    }
    if (size_desc <= 4u) {
        return (uint16_t)(1u + (1u << size_desc));
    }
    if (size_desc == 5u && avail >= 2u) {
        return (uint16_t)(2u + p[1]);
    }
    if (size_desc == 6u && avail >= 3u) {
        return (uint16_t)(3u + (((uint16_t)p[1] << 8) | p[2]));
    }
    return 0u;
}

static uint16_t sdp_parse_cont_offset(const uint8_t *cont, uint16_t avail) {
    if (avail >= 3u && cont[0] == 0x02u) {
        return (uint16_t)(((uint16_t)cont[1] << 8) | cont[2]);
    }
    return 0u;
}

static void sdp_send_attr_chunk(uint16_t hcid, uint8_t rsp_pdu_id,
                                uint8_t tid_hi, uint8_t tid_lo,
                                const uint8_t *full_list, uint16_t full_len,
                                uint16_t max_bytes, uint16_t offset) {
    static uint8_t rsp[400];
    if (max_bytes == 0u) {
        max_bytes = 64u;
    }
    if (max_bytes > 380u) {
        max_bytes = 380u;
    }
    if (offset > full_len) {
        offset = full_len;
    }
    uint16_t chunk = (uint16_t)(full_len - offset);
    if (chunk > max_bytes) {
        chunk = max_bytes;
    }
    for (uint16_t i = 0u; i < chunk; ++i) {
        rsp[7u + i] = full_list[offset + i];
    }
    uint16_t cont_sz = 1u;
    if ((uint32_t)offset + (uint32_t)chunk < (uint32_t)full_len) {
        uint16_t next_off = (uint16_t)(offset + chunk);
        rsp[7u + chunk] = 0x02u;
        rsp[8u + chunk] = (uint8_t)(next_off >> 8);
        rsp[9u + chunk] = (uint8_t)(next_off & 0xFFu);
        cont_sz = 3u;
    } else {
        rsp[7u + chunk] = 0x00u;
    }
    uint16_t param_len = (uint16_t)(2u + chunk + cont_sz);
    rsp[0] = rsp_pdu_id;
    rsp[1] = tid_hi;
    rsp[2] = tid_lo;
    rsp[3] = (uint8_t)(param_len >> 8);
    rsp[4] = (uint8_t)(param_len & 0xFFu);
    rsp[5] = (uint8_t)(chunk >> 8);
    rsp[6] = (uint8_t)(chunk & 0xFFu);
    hci_send_acl(hcid, rsp, (uint16_t)(7u + chunk + cont_sz));
}

static void sdp_handle_pdu(const uint8_t *pdu, uint16_t plen) {
    if (plen < 5u || !g_bt.l2cap_open[0]) {
        return;
    }
    uint8_t pdu_id = pdu[0];
    uint8_t tid_hi = pdu[1];
    uint8_t tid_lo = pdu[2];
    uint16_t hcid = g_bt.l2cap_host_cid[0];

    uint8_t rsp[24];
    static uint8_t full_list[512];
    uint16_t rlen = 0u;

    if (pdu_id == 0x02u) {
        /* SDP_ServiceSearchRequest */
        uint16_t cnt = 0u;
        uint32_t handles[2] = { 0u, 0u };
        if (buf_contains_u16_be(&pdu[5], (uint16_t)(plen - 5u), 0x1124u) ||
            buf_contains_u16_be(&pdu[5], (uint16_t)(plen - 5u), 0x0100u)) {
            handles[cnt++] = 0x00010000u;
        }
        if (buf_contains_u16_be(&pdu[5], (uint16_t)(plen - 5u), 0x1200u) ||
            buf_contains_u16_be(&pdu[5], (uint16_t)(plen - 5u), 0x0100u)) {
            handles[cnt++] = 0x00010001u;
        }
        uint16_t param_len = (uint16_t)(5u + cnt * 4u);
        rsp[rlen++] = 0x03u;
        rsp[rlen++] = tid_hi;
        rsp[rlen++] = tid_lo;
        rsp[rlen++] = (uint8_t)(param_len >> 8);
        rsp[rlen++] = (uint8_t)(param_len & 0xFFu);
        rsp[rlen++] = (uint8_t)(cnt >> 8);
        rsp[rlen++] = (uint8_t)(cnt & 0xFFu);
        rsp[rlen++] = (uint8_t)(cnt >> 8);
        rsp[rlen++] = (uint8_t)(cnt & 0xFFu);
        for (uint16_t i = 0u; i < cnt; ++i) {
            rsp[rlen++] = (uint8_t)(handles[i] >> 24);
            rsp[rlen++] = (uint8_t)(handles[i] >> 16);
            rsp[rlen++] = (uint8_t)(handles[i] >> 8);
            rsp[rlen++] = (uint8_t)(handles[i] & 0xFFu);
        }
        rsp[rlen++] = 0x00u; /* ContinuationState = 0 */
        hci_send_acl(hcid, rsp, rlen);
    } else if (pdu_id == 0x04u && plen >= 13u) {
        /* SDP_ServiceAttributeRequest */
        uint32_t handle = ((uint32_t)pdu[5] << 24) | ((uint32_t)pdu[6] << 16) |
                          ((uint32_t)pdu[7] << 8) | (uint32_t)pdu[8];
        uint16_t max_bytes = (uint16_t)(((uint16_t)pdu[9] << 8) | pdu[10]);
        uint16_t idlist_len = sdp_de_size(&pdu[11], (uint16_t)(plen - 11u));
        uint16_t cont_pos = (uint16_t)(11u + idlist_len);
        uint16_t offset = (idlist_len > 0u && cont_pos < plen)
                              ? sdp_parse_cont_offset(&pdu[cont_pos], (uint16_t)(plen - cont_pos))
                              : 0u;
        if (handle != 0x00010000u && handle != 0x00010001u) {
            /* SDP_ErrorResponse: Invalid Service Record Handle (0x0002) */
            rsp[0] = 0x01u;
            rsp[1] = tid_hi;
            rsp[2] = tid_lo;
            rsp[3] = 0x00u;
            rsp[4] = 0x02u;
            rsp[5] = 0x00u;
            rsp[6] = 0x02u;
            hci_send_acl(hcid, rsp, 7u);
            return;
        }
        uint16_t full_len = (handle == 0x00010001u) ? sdp_build_pnp_record(full_list)
                                                    : sdp_build_hid_record(full_list);
        sdp_send_attr_chunk(hcid, 0x05u, tid_hi, tid_lo, full_list, full_len, max_bytes, offset);
    } else if (pdu_id == 0x06u && plen >= 10u) {
        /* SDP_ServiceSearchAttributeRequest */
        uint16_t pat_len = sdp_de_size(&pdu[5], (uint16_t)(plen - 5u));
        uint16_t max_bytes = 256u;
        uint16_t offset = 0u;
        if (pat_len > 0u && (uint32_t)5u + pat_len + 3u <= plen) {
            uint16_t pos = (uint16_t)(5u + pat_len);
            max_bytes = (uint16_t)(((uint16_t)pdu[pos] << 8) | pdu[pos + 1u]);
            pos += 2u;
            uint16_t idlist_len = sdp_de_size(&pdu[pos], (uint16_t)(plen - pos));
            if (idlist_len > 0u && pos + idlist_len < plen) {
                offset = sdp_parse_cont_offset(&pdu[pos + idlist_len],
                                               (uint16_t)(plen - (pos + idlist_len)));
            }
        }
        int want_pnp = buf_contains_u16_be(&pdu[5], (uint16_t)(plen - 5u), 0x1200u);
        int want_hid = buf_contains_u16_be(&pdu[5], (uint16_t)(plen - 5u), 0x1124u) ||
                       buf_contains_u16_be(&pdu[5], (uint16_t)(plen - 5u), 0x0100u);
        uint16_t olen = 0u;
        full_list[olen++] = 0x36u;
        olen += 2u; /* reserve 16-bit len */
        if (want_hid || !want_pnp) {
            olen += sdp_build_hid_record(&full_list[olen]);
        }
        if (want_pnp) {
            olen += sdp_build_pnp_record(&full_list[olen]);
        }
        uint16_t inner = (uint16_t)(olen - 3u);
        full_list[1] = (uint8_t)(inner >> 8);
        full_list[2] = (uint8_t)(inner & 0xFFu);
        sdp_send_attr_chunk(hcid, 0x07u, tid_hi, tid_lo, full_list, olen, max_bytes, offset);
    }
}

static void hid_pack_sticks(uint8_t dst[6], const pro_input_t *in) {
    dst[0] = (uint8_t)(in->lx & 0xFFu);
    dst[1] = (uint8_t)(((in->lx >> 8) & 0x0Fu) | ((in->ly & 0x0Fu) << 4));
    dst[2] = (uint8_t)((in->ly >> 4) & 0xFFu);
    dst[3] = (uint8_t)(in->rx & 0xFFu);
    dst[4] = (uint8_t)(((in->rx >> 8) & 0x0Fu) | ((in->ry & 0x0Fu) << 4));
    dst[5] = (uint8_t)((in->ry >> 4) & 0xFFu);
}

static void hid_send_input_report(const pro_input_t *in) {
    if (!g_bt.l2cap_open[2] || g_bt.acl_in_flight >= 4u) {
        return;
    }
    uint16_t hcid = g_bt.l2cap_host_cid[2];
    if (g_bt.report_mode == 0x30u) {
        uint8_t pkt[50];
        for (uint32_t i = 0u; i < sizeof(pkt); ++i) {
            pkt[i] = 0u;
        }
        pkt[0] = 0xA1u;
        pkt[1] = 0x30u;
        pkt[2] = g_bt.timer++;
        pkt[3] = 0x90u; /* USB/Full battery + Switch-powered */
        pkt[4] = in->btn_right;
        pkt[5] = in->btn_shared;
        pkt[6] = in->btn_left;
        hid_pack_sticks(&pkt[7], in);
        pkt[13] = 0x08u; /* Vibrator input report ack */
        hci_send_acl(hcid, pkt, 50u);
    } else {
        /* 0x3F basic HID report (13 bytes with 0xA1 header) */
        uint8_t pkt[13];
        uint16_t btns = 0u;
        if (in->btn_right & (1u << 2)) btns |= (1u << 0); /* B */
        if (in->btn_right & (1u << 3)) btns |= (1u << 1); /* A */
        if (in->btn_right & (1u << 0)) btns |= (1u << 2); /* Y */
        if (in->btn_right & (1u << 1)) btns |= (1u << 3); /* X */
        if (in->btn_left  & (1u << 6)) btns |= (1u << 4); /* L */
        if (in->btn_right & (1u << 6)) btns |= (1u << 5); /* R */
        if (in->btn_left  & (1u << 7)) btns |= (1u << 6); /* ZL */
        if (in->btn_right & (1u << 7)) btns |= (1u << 7); /* ZR */
        if (in->btn_shared & (1u << 0)) btns |= (1u << 8);  /* Minus */
        if (in->btn_shared & (1u << 1)) btns |= (1u << 9);  /* Plus */
        if (in->btn_shared & (1u << 3)) btns |= (1u << 10); /* L3 */
        if (in->btn_shared & (1u << 2)) btns |= (1u << 11); /* R3 */
        if (in->btn_shared & (1u << 4)) btns |= (1u << 12); /* Home */
        if (in->btn_shared & (1u << 5)) btns |= (1u << 13); /* Capture */

        uint8_t hat = 8u;
        uint8_t d = in->btn_left & 0x0Fu;
        if (d == 0x02u) hat = 0u;      /* Up */
        else if (d == 0x06u) hat = 1u; /* Up-Right */
        else if (d == 0x04u) hat = 2u; /* Right */
        else if (d == 0x05u) hat = 3u; /* Down-Right */
        else if (d == 0x01u) hat = 4u; /* Down */
        else if (d == 0x09u) hat = 5u; /* Down-Left */
        else if (d == 0x08u) hat = 6u; /* Left */
        else if (d == 0x0Au) hat = 7u; /* Up-Left */

        uint16_t lx16 = (uint16_t)(in->lx << 4);
        uint16_t ly16 = (uint16_t)((4095u - in->ly) << 4);
        uint16_t rx16 = (uint16_t)(in->rx << 4);
        uint16_t ry16 = (uint16_t)((4095u - in->ry) << 4);

        pkt[0] = 0xA1u;
        pkt[1] = 0x3Fu;
        pkt[2] = (uint8_t)(btns & 0xFFu);
        pkt[3] = (uint8_t)(btns >> 8);
        pkt[4] = hat;
        pkt[5] = (uint8_t)(lx16 & 0xFFu);
        pkt[6] = (uint8_t)(lx16 >> 8);
        pkt[7] = (uint8_t)(ly16 & 0xFFu);
        pkt[8] = (uint8_t)(ly16 >> 8);
        pkt[9] = (uint8_t)(rx16 & 0xFFu);
        pkt[10] = (uint8_t)(rx16 >> 8);
        pkt[11] = (uint8_t)(ry16 & 0xFFu);
        pkt[12] = (uint8_t)(ry16 >> 8);
        hci_send_acl(hcid, pkt, 13u);
    }
}

static void hid_send_subcmd_reply(uint8_t subcmd, uint8_t ack,
                                  const uint8_t *data, uint8_t dlen,
                                  const pro_input_t *in) {
    if (!g_bt.l2cap_open[2]) {
        return;
    }
    uint8_t pkt[50];
    for (uint32_t i = 0u; i < sizeof(pkt); ++i) {
        pkt[i] = 0u;
    }
    pkt[0] = 0xA1u;
    pkt[1] = 0x21u;
    pkt[2] = g_bt.timer++;
    pkt[3] = 0x90u;
    pkt[4] = in->btn_right;
    pkt[5] = in->btn_shared;
    pkt[6] = in->btn_left;
    hid_pack_sticks(&pkt[7], in);
    pkt[13] = 0x08u;
    pkt[14] = ack;
    pkt[15] = subcmd;
    for (uint8_t i = 0u; i < dlen && (16u + i) < 50u; ++i) {
        pkt[16u + i] = data[i];
    }
    hci_send_acl(g_bt.l2cap_host_cid[2], pkt, 50u);
}

static void hid_handle_output(const uint8_t *data, uint16_t len, const pro_input_t *in) {
    if (len < 12u) {
        return;
    }
    /* Output report: [0xA2 or 0x52, report_id, timer, rumble[8], subcmd, args...] */
    uint8_t rpt_id = data[1];
    if (rpt_id != 0x01u) {
        return;
    }
    uint8_t subcmd = data[11];
    const uint8_t *args = &data[12];
    uint16_t alen = (uint16_t)(len - 12u);

    if (subcmd == 0x01u) {
        /* Bluetooth manual pairing */
        uint8_t d[1] = { 0x03u };
        hid_send_subcmd_reply(subcmd, 0x81u, d, 1u, in);
    } else if (subcmd == 0x02u) {
        /* Request device info: Pro Controller (0x03), fw 4.22, MAC */
        uint8_t d[12] = {
            0x04u, 0x16u, /* fw 4.22 */
            0x03u, 0x02u, /* Pro Controller */
            g_bt.bd_addr[5], g_bt.bd_addr[4], g_bt.bd_addr[3],
            g_bt.bd_addr[2], g_bt.bd_addr[1], g_bt.bd_addr[0],
            0x01u, 0x02u  /* Use SPI colors */
        };
        hid_send_subcmd_reply(subcmd, 0x82u, d, 12u, in);
    } else if (subcmd == 0x03u && alen >= 1u) {
        /* Set input report mode */
        g_bt.report_mode = args[0];
        hid_send_subcmd_reply(subcmd, 0x80u, 0, 0u, in);
    } else if (subcmd == 0x04u) {
        /* Trigger buttons elapsed time */
        uint8_t d[14] = { 0 };
        hid_send_subcmd_reply(subcmd, 0x83u, d, 14u, in);
    } else if (subcmd == 0x10u && alen >= 5u) {
        /* SPI flash read */
        uint32_t addr = (uint32_t)args[0] | ((uint32_t)args[1] << 8) |
                        ((uint32_t)args[2] << 16) | ((uint32_t)args[3] << 24);
        uint8_t rlen = args[4];
        if (rlen > 29u) rlen = 29u;
        uint8_t d[34];
        d[0] = args[0]; d[1] = args[1]; d[2] = args[2]; d[3] = args[3]; d[4] = rlen;
        for (uint8_t i = 0u; i < rlen; ++i) {
            d[5u + i] = 0xFFu;
        }
        /* Factory stick cal (0x603D..0x604E): 0x540 (1344) X/Y range around 0x800 center */
        static const uint8_t k_cal[18] = {
            0x40u, 0x05u, 0x54u, 0x00u, 0x08u, 0x80u, 0x40u, 0x05u, 0x54u,
            0x00u, 0x08u, 0x80u, 0x40u, 0x05u, 0x54u, 0x40u, 0x05u, 0x54u
        };
        if (addr >= 0x603Du && addr < 0x604Fu) {
            for (uint8_t i = 0u; i < rlen; ++i) {
                uint32_t a = addr + i;
                if (a >= 0x603Du && a < 0x604Fu) {
                    d[5u + i] = k_cal[a - 0x603Du];
                }
            }
        } else if (addr >= 0x6050u && addr < 0x605Cu) {
            /* Body / button / grip colors: Pro Controller dark gray */
            static const uint8_t k_col[12] = {
                0x32u, 0x32u, 0x32u, 0xFFu, 0xFFu, 0xFFu,
                0x32u, 0x32u, 0x32u, 0x32u, 0x32u, 0x32u
            };
            for (uint8_t i = 0u; i < rlen; ++i) {
                uint32_t a = addr + i;
                if (a >= 0x6050u && a < 0x605Cu) {
                    d[5u + i] = k_col[a - 0x6050u];
                }
            }
        } else if (addr >= 0x6086u && addr < 0x60AAu) {
            /* Factory stick parameters (0x6086 Left, 0x6098 Right): deadzone=0x0AE (174) */
            static const uint8_t k_stick_params[18] = {
                0x0Fu, 0x30u, 0x61u, 0xAEu, 0x90u, 0xD9u, 0xD4u, 0x14u, 0x54u,
                0x41u, 0x15u, 0x54u, 0xC7u, 0x79u, 0x9Cu, 0x33u, 0x36u, 0x63u
            };
            for (uint8_t i = 0u; i < rlen; ++i) {
                uint32_t a = addr + i;
                if (a >= 0x6086u && a < 0x6098u) {
                    d[5u + i] = k_stick_params[a - 0x6086u];
                } else if (a >= 0x6098u && a < 0x60AAu) {
                    d[5u + i] = k_stick_params[a - 0x6098u];
                }
            }
        }
        hid_send_subcmd_reply(subcmd, 0x90u, d, (uint8_t)(5u + rlen), in);
    } else if (subcmd == 0x30u && alen >= 1u) {
        g_bt.player_leds = args[0];
        hid_send_subcmd_reply(subcmd, 0x80u, 0, 0u, in);
    } else {
        /* Generic ACK for 0x08, 0x21, 0x38, 0x40, 0x48, etc. */
        hid_send_subcmd_reply(subcmd, 0x80u, 0, 0u, in);
    }
}

static void l2cap_handle_sig(const uint8_t *sig, uint16_t slen) {
    if (slen < 4u) {
        return;
    }
    uint8_t code = sig[0];
    uint8_t id = sig[1];
    uint16_t len = (uint16_t)sig[2] | ((uint16_t)sig[3] << 8);
    const uint8_t *p = &sig[4];
    if (4u + len > slen) {
        return;
    }

    if (code == 0x02u && len >= 4u) {
        /* L2CAP_Connection_Request: psm, scid */
        uint16_t psm = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        uint16_t scid = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
        int idx = -1;
        if (psm == 0x0001u) idx = 0;
        else if (psm == 0x0011u) idx = 1;
        else if (psm == 0x0013u) idx = 2;

        uint8_t rsp[8];
        if (idx >= 0) {
            uint16_t dcid = (uint16_t)(0x0040u + (uint16_t)idx);
            g_bt.l2cap_host_cid[idx] = scid;
            g_bt.l2cap_open[idx] = 1u;
            g_bt.l2cap_cfg_rx[idx] = 0u;
            g_bt.l2cap_cfg_tx[idx] = 0u;
            rsp[0] = (uint8_t)(dcid & 0xFFu);
            rsp[1] = (uint8_t)(dcid >> 8);
            rsp[2] = (uint8_t)(scid & 0xFFu);
            rsp[3] = (uint8_t)(scid >> 8);
            rsp[4] = 0x00u; rsp[5] = 0x00u; /* Success */
            rsp[6] = 0x00u; rsp[7] = 0x00u;
            l2cap_send_sig(0x03u, id, rsp, 8u);
            l2cap_send_config_req(scid);
        } else {
            rsp[0] = 0x00u; rsp[1] = 0x00u;
            rsp[2] = (uint8_t)(scid & 0xFFu);
            rsp[3] = (uint8_t)(scid >> 8);
            rsp[4] = 0x02u; rsp[5] = 0x00u; /* PSM not supported */
            rsp[6] = 0x00u; rsp[7] = 0x00u;
            l2cap_send_sig(0x03u, id, rsp, 8u);
        }
    } else if (code == 0x04u && len >= 4u) {
        /* L2CAP_Configuration_Request -> Reply Success */
        uint16_t dcid = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        uint16_t flags = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
        uint16_t scid = dcid;
        if (dcid >= 0x0040u && dcid <= 0x0042u) {
            uint32_t idx = (uint32_t)(dcid - 0x0040u);
            scid = g_bt.l2cap_host_cid[idx];
            if ((flags & 1u) == 0u) {
                g_bt.l2cap_cfg_rx[idx] = 1u;
                if (g_bt.l2cap_cfg_rx[2] && g_bt.l2cap_cfg_tx[2]) {
                    g_bt.hid_ready = 1u;
                }
            }
        }
        uint8_t rsp[6];
        rsp[0] = (uint8_t)(scid & 0xFFu);
        rsp[1] = (uint8_t)(scid >> 8);
        rsp[2] = 0x00u; rsp[3] = 0x00u;
        rsp[4] = 0x00u; rsp[5] = 0x00u; /* Success */
        l2cap_send_sig(0x05u, id, rsp, 6u);
    } else if (code == 0x05u && len >= 6u) {
        /* L2CAP_Configuration_Response */
        uint16_t scid = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        uint16_t flags = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
        uint16_t res = (uint16_t)p[4] | ((uint16_t)p[5] << 8);
        if (res == 0u && (flags & 1u) == 0u && scid >= 0x0040u && scid <= 0x0042u) {
            uint32_t idx = (uint32_t)(scid - 0x0040u);
            g_bt.l2cap_cfg_tx[idx] = 1u;
            if (g_bt.l2cap_cfg_rx[2] && g_bt.l2cap_cfg_tx[2]) {
                g_bt.hid_ready = 1u;
            }
        }
    } else if (code == 0x06u && len >= 4u) {
        /* L2CAP_Disconnection_Request */
        uint16_t dcid = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        uint16_t scid = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
        if (dcid >= 0x0040u && dcid <= 0x0042u) {
            uint32_t idx = (uint32_t)(dcid - 0x0040u);
            g_bt.l2cap_open[idx] = 0u;
            g_bt.l2cap_cfg_rx[idx] = 0u;
            g_bt.l2cap_cfg_tx[idx] = 0u;
            if (dcid == 0x0042u) {
                g_bt.hid_ready = 0u;
            }
        }
        uint8_t rsp[4] = { p[0], p[1], p[2], p[3] };
        (void)scid;
        l2cap_send_sig(0x07u, id, rsp, 4u);
    } else if (code == 0x0Au && len >= 2u) {
        /* L2CAP_Information_Request */
        uint16_t itype = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        if (itype == 0x0002u) {
            uint8_t rsp[8] = { p[0], p[1], 0x00u, 0x00u, 0x80u, 0x00u, 0x00u, 0x00u };
            l2cap_send_sig(0x0Bu, id, rsp, 8u);
        } else if (itype == 0x0003u) {
            uint8_t rsp[12] = { p[0], p[1], 0x00u, 0x00u, 0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u };
            l2cap_send_sig(0x0Bu, id, rsp, 12u);
        } else {
            uint8_t rsp[4] = { p[0], p[1], 0x01u, 0x00u }; /* Not supported */
            l2cap_send_sig(0x0Bu, id, rsp, 4u);
        }
    }
}

static void bt_dispatch_l2cap(uint16_t cid, const uint8_t *payload, uint16_t l2_len,
                              const pro_input_t *in) {
    if (cid == 0x0001u) {
        l2cap_handle_sig(payload, l2_len);
    } else if (cid == 0x0040u) {
        sdp_handle_pdu(payload, l2_len);
    } else if (cid == 0x0041u && l2_len >= 1u) {
        /* HID Control (0x5x SET_REPORT, 0x7x SET_PROTOCOL, 0x1x HID_CONTROL, 0x6x GET_PROTOCOL) */
        uint8_t hdr_type = (uint8_t)(payload[0] & 0xF0u);
        if (hdr_type == 0x50u) {
            hid_handle_output(payload, l2_len, in);
            uint8_t ack = 0x00u;
            hci_send_acl(g_bt.l2cap_host_cid[1], &ack, 1u);
        } else if (hdr_type == 0x70u || hdr_type == 0x10u || hdr_type == 0x00u) {
            uint8_t ack = 0x00u; /* HANDSHAKE_SUCCESS */
            hci_send_acl(g_bt.l2cap_host_cid[1], &ack, 1u);
        } else if (hdr_type == 0x60u) {
            uint8_t proto[2] = { 0xA0u, 0x01u }; /* Report Protocol */
            hci_send_acl(g_bt.l2cap_host_cid[1], proto, 2u);
        }
    } else if (cid == 0x0042u) {
        /* HID Interrupt Output Report (0xA2 ...) */
        if (l2_len >= 2u && payload[0] == 0xA2u) {
            hid_handle_output(payload, l2_len, in);
        }
    }
}

static void bt_handle_acl(const uint8_t *acl, uint32_t len, const pro_input_t *in) {
    if (len < 4u) {
        return;
    }
    uint8_t pb = (uint8_t)((acl[1] >> 4) & 0x03u);
    if (pb == 0x01u) {
        /* Continuation fragment */
        if (g_bt.reasm_expect == 0u) {
            return;
        }
        uint32_t frag_len = len - 4u;
        if ((uint32_t)g_bt.reasm_len + frag_len > sizeof(g_acl_reasm)) {
            g_bt.reasm_expect = 0u;
            g_bt.reasm_len = 0u;
            return;
        }
        for (uint32_t i = 0u; i < frag_len; ++i) {
            g_acl_reasm[g_bt.reasm_len++] = acl[4u + i];
        }
        if (g_bt.reasm_len >= g_bt.reasm_expect) {
            uint16_t cid = g_bt.reasm_cid;
            uint16_t l2_len = g_bt.reasm_expect;
            g_bt.reasm_expect = 0u;
            g_bt.reasm_len = 0u;
            bt_dispatch_l2cap(cid, g_acl_reasm, l2_len, in);
        }
        return;
    }

    /* Start fragment (PB=10b or PB=00b) */
    g_bt.reasm_expect = 0u;
    g_bt.reasm_len = 0u;
    if (len < 8u) {
        return;
    }
    uint16_t l2_len = (uint16_t)acl[4] | ((uint16_t)acl[5] << 8);
    uint16_t cid = (uint16_t)acl[6] | ((uint16_t)acl[7] << 8);
    const uint8_t *payload = &acl[8];
    uint32_t avail = len - 8u;
    if (avail >= l2_len) {
        bt_dispatch_l2cap(cid, payload, l2_len, in);
    } else if (l2_len <= sizeof(g_acl_reasm)) {
        g_bt.reasm_cid = cid;
        g_bt.reasm_expect = l2_len;
        g_bt.reasm_len = (uint16_t)avail;
        for (uint32_t i = 0u; i < avail; ++i) {
            g_acl_reasm[i] = payload[i];
        }
    }
}
