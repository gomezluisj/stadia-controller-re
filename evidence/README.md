# Evidence directory

No copyrighted firmware binaries are hosted here — only hashes, console excerpts, and raw-capture summaries that let a third party check claims against their own dumps (`sha256sum -c SHA256SUMS.txt` on the files you extract; note byte lengths are listed for 6 of the 8 artifacts, and no full 16 MB NOR or KVS partition hash is present yet).

| File | Claim it supports |
|---|---|
| `SHA256SUMS.txt` | §8 reference hashes (slot/bootloader/flashloader artifacts only; excludes KVS/full-NOR dump) |
| `flexspi_erase_verify.log` | §3 arbitrary erase primitive (abridged REV 4.1 console summary, not a raw HID wire capture) |
| `ble_bruce_input.log` | §6 BLE HOGP input flow under bruce (`/dev/input/js0`) |
| `cdc_i2c_scan.log` | Live `LPI2C1`/`LPI2C2` register dump (`0x1A` `WM8904`, `0x3B` `TS3A227E`, `0x30` `LP5562`) |
| `cdc_l2r2_gpio2_10.log` | 15-GPIO sweep proving active-LOW `GPIO2_10 = 0` powers `L2`/`R2` Hall triggers (`IN8`/`IN13`) + full-press ranges |
| `cdc_bt_sdp_hid.log` | Redacted Classic BT HCI/ACL trace of paginated SDP, SSP + encryption, and Switch Pro Controller HID bring-up on macOS |
| `cdc_switch2_bt_hid.log` | Redacted Classic BT HCI/ACL trace of Nintendo Switch 2 pairing (`Auth=0x04`, Sniff Mode, L2CAP MTU echo, `L+R` `0x3F`, full Pro Controller init) |
