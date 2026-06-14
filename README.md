# SSH Massen-Brute-Forcer mit libssh2
```bash
## Original: 2014 Refaktorisiert: 2026

### Kompilierung

gcc -Wall -Wextra -Wformat=2 -Wshadow -o pscan pscan.c \
          -I/path/to/libssh2/include -L/path/to/libssh2/lib \
          -lssh2 -lcrypto

Beschreibung
Dieses Tool scannt entweder eine Liste von IPs oder ein komplettes /16-Netzwerk nach offenen SSH-Ports und versucht dann, mit den angegebenen Benutzernamen und Passwörtern eine Verbindung herzustellen. Gefundene Kombinationen werden in einer Datei namens vuln.txt gespeichert.

In pass.lst: $user     = Das Passwort ist exakt identisch mit dem Benutzernamen.
             $user123  = Das Passwort setzt sich aus dem Benutzernamen und der direkt angehängten Zeichenfolge "123" zusammen.

| User   | Eingang in pass.lst | Result. Passwort |
| ------ | ------------------- | ---------------- |
| oracle | $user               | oracle           |
| oracle | $user123            | oracle123        |
| admin  | $userpass           | adminpass        |
| root   | $user!              | root!            |
| test   | passwort            | passwort         |
| test   | prefix$user         | prefixtest       |

Nutzung
./brute -f ip.lst   -t 3 -user users.lst -pass pass.lst -p 22 -c "uname -a"
./brute -b 10.10    -t 3 -user users.lst -pass pass.lst -p 22 -c "uname -a"

Argumente
-f: Pfad zur Datei mit den zu scannenden IP-Adressen (eine pro Zeile).
-n: /16-Netzwerk, das gescannt werden soll (z. B. 192.168.1.0/16).
-user: Pfad zur Datei mit den Benutzernamen (eine pro Zeile).
-pass: Pfad zur Datei mit den Passwörtern (eine pro Zeile).
-p: Port, auf dem SSH-Verbindungen getestet werden (Standard: 22).
-t: Timeout in Sekunden für jede Verbindung (Standard: 3).
-c: Kommando, das auf dem Remote-Server ausgeführt werden soll.

Hinweis
Dieses Tool ist für legale Penetrationstests gedacht. Bitte verwenden Sie es verantwortungsbewusst und nur mit ausdrücklicher Genehmigung des Eigentümers der Zielsysteme. Der Autor übernimmt keine Haftung für Schäden, die durch die Nutzung dieses Tools entstehen

Autor
dr4c0_
```
