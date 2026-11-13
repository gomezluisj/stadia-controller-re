# Evidence directory

No copyrighted firmware binaries are hosted here — only hashes, console excerpts, and raw-capture summaries that let a third party check claims against their own dumps (`sha256sum -c SHA256SUMS.txt` on the files you extract; note byte lengths are listed only for 3 of the 6 artifacts, and no full 16 MB NOR or KVS partition hash is present yet).

| File | Claim it supports |
|---|---|
| `SHA256SUMS.txt` | §8 reference hashes (slot/bootloader/flashloader artifacts only; excludes KVS/full-NOR dump) |
| `flexspi_erase_verify.log` | §3 arbitrary erase primitive (abridged REV 4.1 console summary, not a raw HID wire capture) |
| `ble_bruce_input.log` | §6 BLE HOGP input flow under bruce (`/dev/input/js0`) |
