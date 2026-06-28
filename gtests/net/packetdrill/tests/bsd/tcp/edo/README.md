# TCP EDO `.pkt` tests (FreeBSD)

Integration tests for the TCP EDO (Extended Data Offset) support against the
modified FreeBSD stack. Run a single test (as root, on the EDO kernel):

```sh
sudo ./packetdrill tests/bsd/tcp/edo/<name>.pkt
```

Option kinds match the kernel (`netinet/tcp.h`): EDO Supported = **79**,
EDO Extension = **80** (changed from 77/78 in commit `2ca52542`).

| Test | Checks | Status against the EDO kernel |
|---|---|---|
| `edo-1-negotiation.pkt` | SYN offers `edoOK`; stack echoes `edoOK` (kind 79) in the SYN-ACK and puts no EDO Extension there | **pass** |
| `edo-2-extension.pkt` | After negotiation the stack's data segment carries an EDO Extension (kind 80) padded with dummy NOPs to 80 option bytes (`Header_Length` = 25 words, real header 100 B) | **pass** |
| `edo-3-options-over-60.pkt` | Inbound segment whose real header (via `Header_Length`) exceeds the 60-byte doff region; payload is located via `Header_Length` and `read()` returns exactly 100 | **pass** (receive side implemented) |
| `edo-4-stray-extension.pkt` | An EDO Extension on a connection that never negotiated EDO must not RST/drop (kernel-consistent: ignored) | **pass** |
| `edo-5-bad-header-length-too-large.pkt` | Inbound EDO Extension whose `Header_Length*4` exceeds `doff*4 + tlen` is dropped (no RST); a plain retransmit is then delivered | **pass** |
| `edo-6-bad-header-length-too-small.pkt` | Inbound EDO Extension whose `Header_Length*4` is smaller than `doff*4` is dropped (no RST); a plain retransmit is then delivered | **pass** |

## Notes on the current kernel test build

- **Send side** (`netinet/tcp_output.c`) pads every outbound EDO data segment
  with dummy NOPs up to `EDO_TEST_OLEN` (80 option bytes) so the real header
  exceeds 60 B on send. `edo-2` asserts that exact layout; if `EDO_TEST_OLEN`
  changes, update the expected `Header_Length` and NOP count there.
- **Receive side** (`netinet/tcp_input.c`) now relocates the payload boundary to
  `Header_Length` and validates `doff*4 <= Header_Length*4 <= doff*4 + tlen`,
  dropping segments that violate the bounds. `edo-3` (valid) plus `edo-5`/`edo-6`
  (out-of-bounds) cover this.
