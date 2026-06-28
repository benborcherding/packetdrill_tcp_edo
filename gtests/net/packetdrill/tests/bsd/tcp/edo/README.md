# TCP EDO `.pkt` tests (FreeBSD)

Integration tests for TCP **EDO (Extended Data Offset**,
draft-ietf-tcpm-tcp-edo-15) against the modified FreeBSD stack. EDO decouples the
4-bit TCP **Data Offset** (`doff`, max 60 B header) from the *real* header length:
an **EDO Extension** option carries a 16-bit `Header_Length` (in 32-bit words)
that names where the options truly end and the payload begins. This lets a header
carry more than 40 option bytes while `doff` keeps pointing at a legal boundary.

Run a single test as root **on the EDO kernel** (the tests talk to the live
stack, so they must run inside the modified FreeBSD kernel, e.g. the UTM VM):

```sh
sudo ./packetdrill tests/bsd/tcp/edo/<name>.pkt
```

Option kinds match the kernel (`netinet/tcp.h`): **EDO Supported = kind 79**,
**EDO Extension = kind 80** (changed from 77/78 in sys commit `2ca52542`).

## Notation: `N*opt`

Long option runs use the repeat shorthand `N*opt`, e.g. `40*nop` is 40 NOPs.
It is byte-for-byte identical to writing the option out N times and works for any
option that takes no inline argument (mainly `nop`/`eol`). Example:

```
<edo 25,76*nop>      ==  <edo 25,nop,nop, ... (76 nops)>
```

## Summary

| Test | Direction exercised | Expected | Status |
|---|---|---|---|
| `edo-1-negotiation.pkt`            | negotiation       | SYN-ACK echoes `edoOK`, no Extension | **pass** |
| `edo-2-extension.pkt`              | send (data)       | data segment carries Extension + dummy NOPs (header 100 B) | **pass** |
| `edo-3-options-over-60.pkt`        | receive (valid)   | payload located via `Header_Length`; `read()` == 100 | **pass** |
| `edo-4-stray-extension.pkt`        | receive (non-EDO) | stray Extension ignored, no RST | **pass** |
| `edo-5-bad-header-length-too-large.pkt` | receive (invalid) | `Header_Length` past segment → drop, no RST | **pass** |
| `edo-6-bad-header-length-too-small.pkt` | receive (invalid) | `Header_Length` < `doff` → drop, no RST | **pass** |

All six pass against the current EDO kernel (`#1`, source state of sys `645e9136`).

---

## `edo-1-negotiation.pkt` — capability negotiation

**Setup.** A passive socket (`listen`). The remote sends a SYN offering
`<mss 1460,sackOK,edoOK>`.

**Expected behaviour.** The stack MUST echo `edoOK` (EDO Supported, kind 79) in
its SYN-ACK and MUST NOT place an EDO Extension in the SYN-ACK:

```
0.100 < S 0:0(0) win 65535 <mss 1460,sackOK,edoOK>
0.100 > S. 0:0(0) ack 1     <mss 1460,sackOK,edoOK>
```

**Why.** EDO is a negotiated capability (RFC draft §3). The Extension may only
appear once *both* sides have advertised EDO Supported, so it must be absent from
the SYN-ACK itself; advertising `edoOK` back is the server's half of the
handshake. This guards the `tcp_syncache`/`tcp_output` SYN-ACK path that sets
`TF2_EDO_SUPPORTED`.

**Pass criteria.** The SYN-ACK matches the `edoOK` option exactly and the
connection reaches ESTABLISHED (`accept` succeeds).

> Note: the very first run after a cold VM boot can hit a packetdrill *timing*
> tolerance (inbound injected a few hundred ms late). That is a scheduling
> artifact, not an EDO failure — re-running passes deterministically.

## `edo-2-extension.pkt` — send side, header beyond 60 bytes

**Setup.** Full EDO negotiation, then the server `write()`s 100 bytes.

**Expected behaviour.** Every non-SYN segment the stack emits on a negotiated
connection carries an EDO Extension (kind 80). The current kernel *test build*
additionally pads each outbound EDO data segment with dummy NOPs up to
`EDO_TEST_OLEN` (80 option bytes) to deliberately push the real header past the
60-byte `doff` limit:

```
0.300 > P. 1:101(100) ack 1 <edo 25,76*nop>
```

Resulting layout: EDO Extension (4 B) + 76 NOPs = 80 option bytes.
`doff` covers only up to & incl. the Extension → `doff = 6` (24 B), while
`Header_Length = (20 + 80) / 4 = 25` words = 100 B real header.

**Why.** This proves the **send** path can build and correctly stamp an
oversized header: `doff` stays legal (6 ≤ 15) yet `Header_Length` advertises the
true 100-byte header, with the extra option bytes living in the extended region
beyond `doff`. See the "TEST SEGMENT FOR ADDING DUMMY OPTIONS" block and the
`th_off`/`Header_Length` split in `netinet/tcp_output.c`.

**Pass criteria.** The captured data segment matches `doff = 6`, the EDO
Extension `Header_Length = 25`, and exactly 76 trailing NOPs.

> If `EDO_TEST_OLEN` changes in the kernel, update the expected `Header_Length`
> (= `(20 + EDO_TEST_OLEN)/4`) and NOP count (`EDO_TEST_OLEN - 4`) here.

## `edo-3-options-over-60.pkt` — receive side, valid oversized header

**Setup.** Full EDO negotiation. The remote injects a 100-byte data segment whose
visible header (`doff`) covers only the EDO Extension, but whose real header —
named by `Header_Length = 16` words = 64 B — carries 40 extra option bytes in the
extended region:

```
0.300 < P. 1:101(100) ack 1 win 65535 <edo 16,40*nop>
0.300 read(4, ..., 1000) = 100
```

**Expected behaviour.** The stack must locate the payload at offset 64 (from
`Header_Length`), **not** at `doff*4 = 24`. `read()` therefore returns exactly
**100** bytes.

**Why.** This is the whole point of EDO on **receive**: honouring `Header_Length`
instead of `doff` for the payload boundary. The kernel relocates the boundary in
`tcp_do_segment` (`netinet/tcp_input.c`): when an EDO Extension is present it
adds `real_off - doff*4` to `drop_hdrlen` and subtracts it from `tlen`, so the 40
extended NOPs are treated as header, not data. Without this, a stack using `doff`
would mis-deliver the 40 NOPs and `read()` would return 140.

**Pass criteria.** `read()` returns 100 (and the bytes are the payload, not the
NOPs).

## `edo-4-stray-extension.pkt` — non-EDO connection, stray Extension

**Setup.** A **plain** handshake with NO `edoOK` (`<mss 1460,sackOK,nop,nop>`), so
EDO is never negotiated. The remote then injects a data segment that nonetheless
carries an EDO Extension (within `doff`, no extended region):

```
0.100 < S 0:0(0) win 65535 <mss 1460,sackOK,nop,nop>
...
0.300 < P. 1:101(100) ack 1 win 65535 <edo 6>
0.300 read(4, ..., 1000) = 100
```

**Expected behaviour.** Because EDO was never negotiated, the stack must NOT act
on the Extension — and crucially must NOT RST or drop the connection. The data is
delivered normally (`read()` == 100).

**Why.** Defends against a stray/unsolicited Extension being mis-parsed or
treated as an error on a connection that never opted in. The kernel only honours
`Header_Length` when EDO was negotiated for that PCB; otherwise the option is
inert. This is the negative counterpart to `edo-3`.

**Pass criteria.** No RST/abort; `read()` returns 100; `close()` succeeds.

## `edo-5-bad-header-length-too-large.pkt` — receive side, out-of-bounds (high)

**Setup.** Full EDO negotiation. The remote injects a data segment claiming a
`Header_Length` that points **past the end of the segment**:

```
0.300 < P. 1:101(100) ack 1 win 65535 <edo 60,40*nop>   // claims 60 words = 240 B
0.400 < P. 1:101(100) ack 1 win 65535                   // plain retransmit
0.400 read(4, ..., 1000) = 100
```

Here `doff*4 = 24` and the segment carries 40 NOPs + 100 B payload, so the upper
bound is `24 + (40 + 100) = 164` B. The claimed header is `60*4 = 240 > 164`.

**Expected behaviour.** The stack MUST reject the segment (`goto drop`) — silently,
without a RST and without advancing `rcv_nxt`. The subsequent **plain** retransmit
of the same data (seq 1:101) is then delivered normally, so `read()` returns 100.

**Why.** Exercises the receive-side sanity check
`doff*4 <= Header_Length*4 <= doff*4 + tlen` in `tcp_input.c`. A `Header_Length`
beyond the segment would otherwise push `drop_hdrlen` past the mbuf and make the
stack treat non-existent bytes as header (or underflow `tlen`). The recovery
segment also *proves the bogus one was dropped, not accepted*: had it been
accepted, `rcv_nxt` would already be 101, the retransmit would be a pure
duplicate, no new data would be delivered, and `read()` would block — failing the
test.

**Pass criteria.** No RST; the bogus segment yields no data; the plain retransmit
delivers 100 bytes.

## `edo-6-bad-header-length-too-small.pkt` — receive side, out-of-bounds (low)

**Setup.** Identical to `edo-5` but the claimed header is **shorter** than the
visible (`doff`) header:

```
0.300 < P. 1:101(100) ack 1 win 65535 <edo 4,40*nop>    // claims 4 words = 16 B
0.400 < P. 1:101(100) ack 1 win 65535                   // plain retransmit
0.400 read(4, ..., 1000) = 100
```

`doff*4 = 24` B, but `Header_Length*4 = 16 < 24`.

**Expected behaviour.** Same as `edo-5`: the segment is dropped (`goto drop`),
no RST, `rcv_nxt` unchanged; the plain retransmit then delivers 100 bytes.

**Why.** The lower-bound half of the same check: the real header may never be
*shorter* than the visible header `doff` already committed to (that would imply
options inside `doff` lie beyond the payload boundary — incoherent). Together with
`edo-3` (valid) and `edo-5` (too high), this brackets the `Header_Length`
validation from both sides.

**Pass criteria.** No RST; bogus segment yields no data; plain retransmit
delivers 100 bytes.

---

## Mapping tests → kernel mechanisms

- **Negotiation** (`tcp_syncache.c` / `tcp_output.c`, `TF2_EDO_SUPPORTED`):
  `edo-1`.
- **Send-side header split** (`tcp_output.c`, `th_off` vs `Header_Length`,
  dummy-NOP test segment): `edo-2`.
- **Receive-side payload relocation + bounds check** (`tcp_input.c`,
  `drop_hdrlen`/`tlen` adjust, `goto drop`): `edo-3` (valid), `edo-5` (high),
  `edo-6` (low).
- **Non-negotiated inertness** (no PCB EDO state → option ignored): `edo-4`.
