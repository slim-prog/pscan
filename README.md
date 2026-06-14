 * pscan.c – SSH Massen-Brute-Forcer mit libssh2
 
 
 * Kompilierung: 
 * gcc -Wall -Wextra -o pscan pscan.c \
       -I/path/to/libssh2/include \
       -L/path/to/libssh2/lib \
       -lssh2 -lcrypto
  
 * Autor: dr4c0

 * ** Beschreibung:
 * Dieses Tool scannt entweder eine Liste von IPs oder ein komplettes /16-Netzwerk nach offenen SSH-Ports und versucht dann, 
 * mit den angegebenen Benutzernamen und Passwörtern eine Verbindung herzustellen. 
 * Gefundene Kombinationen werden in einer Datei namens "vuln.txt" gespeichert.

 * ** Nutzung:
 * 1. Mit einer IP-Liste:
 *    ./brute -f ip.lst -user users.lst -pass pass.lst -p 22 -t 10 -c "name -a"
 * 2. Mit einem /16-Netzwerk:
 *    ./brute -n 192.168.1.0/16 -user users.lst -pass pass.lst -p 22 -t 10 -c "uname -a"    

 * ** Argumente:
 * -f: Pfad zur Datei mit den zu scannenden IP-Adressen (eine pro Zeile).
 * -n: /16-Netzwerk, das gescannt werden soll (z.B. 192.168.1.0/16).
 * -user: Pfad zur Datei mit den Benutzernamen (eine pro Zeile).
 * -pass: Pfad zur Datei mit den Passwörtern (eine pro Zeile).
 * -p: Port, auf dem SSH-Verbindungen getestet werden (Standard: 22).
 * -t: Timeout in Sekunden für jede Verbindung (Standard: 3).
 * -c: Kommando, das auf dem Remote-Server ausgeführt werden soll.

 * ** Hinweis:
 * Dieses Tool ist für legale Penetrationstests gedacht. Bitte verwenden Sie es verantwort
 * ungsbewusst und nur mit ausdrücklicher Genehmigung des Eigentümers der Zielsysteme. 
 * Der Autor übernimmt keine Haftung für Schäden, die durch die Nutzung dieses Tools entstehen.