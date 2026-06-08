# TCP EDO `.pkt` tests (FreeBSD)

Integration tests for the TCP EDO (Extended Data Offset) support against the
modified FreeBSD stack. Run a single test (as root, on the EDO kernel):

```sh
sudo ./packetdrill tests/bsd/tcp/edo/<name>.pkt
```

| Test | Checks | Status against the EDO kernel |
|---|---|---|
| `edo-1-negotiation.pkt` | SYN offers `edoOK`; stack echoes `edoOK` (kind 77) in the SYN-ACK and puts no EDO Extension there | **pass** |
| `edo-2-extension.pkt` | After negotiation the stack's data segment carries an EDO Extension (`edo`, kind 78) | **pass** |
| `edo-3-options-over-60.pkt` | Inbound segment whose real header (via `Header_Length`) exceeds the 60-byte doff region; payload must be located via `Header_Length` | **FAIL — known kernel gap (see below)** |
| `edo-4-stray-extension.pkt` | An EDO Extension on a connection that never negotiated EDO must not RST/drop (kernel-consistent: ignored) | **pass** |

## Known kernel gap exposed by `edo-3`

The EDO **send** side works (negotiation + emitting the Extension), but the
**receive** side does not relocate the payload past the extended option region:
`read()` returns 140 instead of 100 because the stack uses `doff*4` (24 B) as the
header length and delivers the 40 extra option bytes as data.

Root cause in the kernel fork: `tcp_input.c` parses the EDO Extension into
`to->to_edo_hdr_len` (`tcp_dooptions`), but that value is never used — the payload
offset `drop_hdrlen` is derived solely from `th_off` (doff). To honour EDO on
receive, `drop_hdrlen` must be taken from `Header_Length` when an EDO Extension is
present on a negotiated connection.

`edo-3` is intentionally kept as the *correct-behaviour* test; it will turn green
once the kernel implements receive-side `Header_Length` handling.
