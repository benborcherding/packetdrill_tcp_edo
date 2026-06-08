# packetdrill mit TCP-EDO-Unterstützung

Dieser Fork erweitert packetdrill um **TCP EDO (Extended Data Offset,
[draft-ietf-tcpm-tcp-edo-15](https://www.ietf.org/archive/id/draft-ietf-tcpm-tcp-edo-15.txt))**,
um einen modifizierten FreeBSD-TCP-Stack damit zu testen — sowohl das **Senden**
korrekter EDO-Segmente als auch das **Prüfen** empfangener EDO-Segmente.

Diese Datei richtet sich an das Kernel-Team: Sie beschreibt, was der Fork kann,
wie man EDO in `.pkt`-Skripten ausdrückt und wie man baut/testet.

---

## 1. Was EDO ändert (und warum packetdrill angepasst werden musste)

EDO entkoppelt zwei Dinge, die TCP bisher gleichsetzt:

- **Data Offset (`doff`)** – 4 Bit, max. 60 Byte Header.
- **Tatsächliche Header-/Optionslänge** – kann mit EDO **> 60 Byte** sein.

packetdrill hat `doff*4` überall als alleinige Header-/Payload-Grenze benutzt.
Der Fork führt eine davon getrennte **effektive Header-Länge** ein (`struct
packet.tcp_header_len_override`): ohne EDO ist sie identisch zu `doff*4` (keine
Verhaltensänderung), mit EDO kommt sie aus dem `Header_Length`-Feld der
EDO-Extension.

---

## 2. EDO-Wire-Format (wie dieser Fork es abbildet)

Angeglichen an den FreeBSD-Teststack (native Option-Kinds, **keine**
RFC-6994-Experimental-Variante):

### EDO Supported (2 Byte) — nur in SYN / SYN-ACK
```
+--------+--------+
| Kind=77| Len=2  |
+--------+--------+
```

### EDO Extension (4 Byte) — ab dem ersten Nicht-SYN-Segment
```
+--------+--------+--------+--------+
| Kind=78| Len=4  |  Header_Length  |   <- 16 Bit, Network Byte Order
+--------+--------+--------+--------+
```
- `Header_Length` = **gesamte TCP-Header-Länge in 32-Bit-Worten**
  (`(20 + alle Optionen) / 4`), Network Byte Order. **Worte, nicht Bytes.**
- **Nur die 4-Byte-Variante** wird unterstützt (der Teststack implementiert
  keine 6-Byte-Variante mit `Segment_Length`).

Konstanten (`gtests/net/packetdrill/tcp.h`):
```c
#define TCPOPT_EDO_SUPPORTED 77
#define TCPOLEN_EDO_SUPPORTED 2
#define TCPOPT_EDO_EXTENSION 78
#define TCPOLEN_EDO_EXTENSION 4   /* Kind, Len, Header_Length(16 Bit) */
```

### doff-Konvention
`doff` deckt die Optionen **bis einschließlich der EDO-Extension** ab; alle
Optionen *danach* liegen in der „erweiterten" Region jenseits `doff`. Das
`Header_Length`-Feld trägt das echte Gesamtmaß.

---

## 3. DSL: EDO in `.pkt`-Skripten

Zwei neue TCP-Options-Schlüsselwörter:

| Schlüsselwort | Bedeutung |
|---|---|
| `edoOK` | EDO Supported (Kind 77). Nur in SYN / SYN-ACK sinnvoll. |
| `edo <header_length>` | EDO Extension (Kind 78). `<header_length>` = Gesamt-Header in **32-Bit-Worten** (geht als `Header_Length` auf die Leitung). |

Beispiele (Optionen müssen wie immer 4-Byte-ausgerichtet sein):
```
# Aushandlung
<mss 1460,sackOK,edoOK>

# Daten-Segment mit EDO-Extension; Header_Length = 6 Worte (24-Byte-Header)
<edo 6>

# Erweiterte Region: Optionen hinter der EDO-Extension dürfen > 60 Byte ergeben
<mss 1460,edo 17,sack 1000:2000 3000:4000 ...>
```

`packet_to_string` rendert EDO genauso zurück (`edoOK`, `edo <n>`), d. h.
Fehlschläge zeigen lesbare Diffs.

> Hinweis: `<header_length>` wird **nicht** automatisch berechnet — der im Skript
> angegebene Wert geht 1:1 auf die Leitung. Das ist Absicht (packetdrill-Prinzip
> „Skript = exakte Wire-Bytes") und erlaubt auch Negativtests mit falschen Werten.

---

## 4. Parser-Verhalten beim Empfang (kernel-konsistent)

Der FreeBSD-Teststack lehnt fehlerhaftes EDO **nicht** ab (kein Drop/RST): eine
EDO-Extension mit unerwarteter Länge wird ignoriert, und `Header_Length` wird
nicht gegen `doff`/Segmentgröße geprüft. packetdrill spiegelt das:

- Das Header-Längen-**Override wird nur angewendet**, wenn die Extension voll
  gültig/benutzbar ist: Länge == 4 **und** `doff*4 ≤ Header_Length*4 ≤ Segment`.
- Andernfalls (falsche Länge, `Header_Length` außerhalb, Extension jenseits
  `doff`) → behandelt als **Nicht-EDO** (Override 0), Parse erfolgreich.
- **Einzige harte Ablehnung:** eine Option, deren Länge über den Puffer
  hinausläuft → `PACKET_BAD` (Speichersicherheit, kein Out-of-bounds-Read).

---

## 5. Bauen & Testen

Alle Befehle aus `gtests/net/packetdrill/`.

```sh
./configure          # wählt das passende Makefile.<Plattform>
make                 # baut packetdrill + Unit-Test-Binaries
make tests           # hermetische Unit-Tests (kein Kernel nötig)
```

EDO-Logik ist hermetisch getestet (`tcp_options_edo_test`): Build-, Parse- und
Round-Trip-Fälle plus Negativ-/Bounds-Tests. `make tests` muss grün sein.

### `.pkt`-Tests gegen den Stack (FreeBSD, als root)
packetdrill testet den **laufenden Kernel** — EDO-Tests brauchen also den
EDO-Kernel. Einmalig (für packetdrill unter `sudo`):
```sh
sudo sysctl vm.old_mlock=1
sudo kldload if_tun        # packetdrill local mode nutzt tun(4)
```
Einzeltest:
```sh
sudo ./packetdrill pfad/zum/test.pkt
```

---

## 6. Beispiel-`.pkt` (Server-Seite, Aushandlung)

> Vorlage — die genaue Optionsreihenfolge im SYN-ACK hängt vom Stack ab; mit
> `tcpdump` gegen den echten Kernel abgleichen und ggf. anpassen.

```
0.000 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3
0.000 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
0.000 bind(3, ..., ...) = 0
0.000 listen(3, 1) = 0

// Remote bietet EDO im SYN an
0.100 < S 0:0(0) win 65535 <mss 1460,sackOK,edoOK>
// Stack MUSS edoOK im SYN-ACK zurückgeben (Kind 77)
0.100 > S. 0:0(0) ack 1 <mss 1460,sackOK,edoOK>
0.200 < . 1:1(0) ack 1 win 65535
0.200 accept(3, ..., ...) = 4

// Ab hier trägt jedes Nicht-SYN-Segment des Stacks eine EDO-Extension.
0.300 write(4, ..., 100) = 100
0.300 > P. 1:101(100) ack 1 <edo ...>
```

Syntax eines Skripts ohne Stack prüfen:
```sh
./packetdrill --dry_run pfad/zum/test.pkt
```

---

## 7. Stand & Grenzen

- Unterstützt: native Kinds 77/78, **nur** 4-Byte-Extension, `Header_Length` in
  Worten, doff-Entkopplung in Build, Parse, Iterator, Ausgabe und Vergleich.
- Nicht abgebildet: 6-Byte-Variante mit `Segment_Length` (vom Teststack nicht
  implementiert).
- Geänderte Dateien: `tcp.h`, `tcp_options.h`, `tcp_packet.c`, `packet.{h,c}`,
  `packet_parser.c`, `lexer.l`, `parser.y`, `tcp_options_to_string.c`,
  `run_packet.c` sowie Tests (`tcp_options_edo_test.c`,
  `packet_to_string_test.c`).
- `parser.c`/`parser.h`/`lexer.c` werden generiert — **nie** von Hand editieren;
  immer `parser.y` / `lexer.l` ändern und neu bauen (bison/flex).
