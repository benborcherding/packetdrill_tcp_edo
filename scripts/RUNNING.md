# EDO-Tests ausführen

Kurzanleitung. Was die einzelnen Tests prüfen, steht in
[`tests/bsd/tcp/edo/README.md`](../gtests/net/packetdrill/tests/bsd/tcp/edo/README.md).

EDO-Tests müssen **im modifizierten FreeBSD-EDO-Kernel** laufen — auf dem Mac in
einer FreeBSD-VM (UTM), nicht in Docker. VM-Einrichtung: `.claude/FREEBSD_BUILD_ENV.md`
(lokal).

## Voraussetzung: SSH-Alias zur VM

In `~/.ssh/config`, mit key-auth + NOPASSWD-sudo (damit nichts nachfragt):

```
Host fbsd-edo
    HostName <VM-IP>          # UTM vergibt per DHCP; ggf. anpassen
    User <user>
    IdentityFile ~/.ssh/id_rsa
```

VM-IP finden, falls der Alias ins Leere läuft: `arp -a | grep 192.168.6`
(UTM shared network) oder in der VM `ifconfig`.

## Lokal bauen (macOS) — Unit-Tests, kernel-unabhängig

Aus `gtests/net/packetdrill/`:

```sh
./configure && make      # baut packetdrill (keine Warnungen erlaubt)
make tests               # Unit-Tests (checksum / parser / edo)
```

## Integrationstests auf der VM

Der Runner synchronisiert die Quellen in die VM, baut dort und führt die Suite
als root aus (mit Retry gegen den Kaltstart-Timing-Ausreißer). Aus dem
Repo-Root:

```sh
scripts/run_vm.sh                                     # ganze EDO-Suite
scripts/run_vm.sh tests/bsd/tcp/edo/edo-3-options-over-60.pkt   # ein Test
SKIP_BUILD=1 scripts/run_vm.sh                        # ohne Rebuild (schneller)
RETRIES=5 scripts/run_vm.sh                           # mehr Retries
```

Konfiguration über Env: `FBSD_VM` (ssh-Alias, Default `fbsd-edo`), `FBSD_DEST`
(Pfad in der VM, Default `packetdrill`). Exit-Code ≠ 0, wenn ein Test
fehlschlägt (CI-tauglich).

Einzelnen Test manuell in der VM:

```sh
ssh fbsd-edo 'cd packetdrill && sudo ./packetdrill tests/bsd/tcp/edo/edo-1-negotiation.pkt'
```

## Kernel aktualisieren (wenn sich der EDO-Stack ändert)

Betroffene Dateien (typisch `netinet/tcp.h`, `tcp_input.c`, `tcp_output.c`) nach
`/usr/src/sys/netinet/` der VM kopieren (Backup nicht vergessen), dann:

```sh
ssh fbsd-edo 'cd /usr/src && sudo make -j4 buildkernel KERNCONF=GENERIC \
            && sudo make installkernel KERNCONF=GENERIC && sudo reboot'
```

Nach dem Reboot `uname -v` prüfen und die Suite erneut laufen lassen.
