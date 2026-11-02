# Evidence directory

No copyrighted firmware binaries are hosted here — only hashes, console logs, and
raw-capture excerpts that let a third party verify each claim of the README
against their own dumps (verify with `sha256sum -c SHA256SUMS.txt` after
producing your own copies via stadiatool + the §3 FlexSPI primitives).

| File | Claim it supports |
|---|---|
| `SHA256SUMS.txt` | §8 reference hashes (full, untruncated) |
| `flexspi_erase_verify.log` | §3 arbitrary erase primitive (REV 4.1 run) |
| `ble_bruce_input.log` | §6 BLE HOGP input flow under bruce (`/dev/input/js0`) |
