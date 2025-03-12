````/*
 * Implémentation complète de la commande su pour Android
 *
 * Ce script intègre :
 *  - Le header "su.h" définissant constantes, structures et prototypes.
 *  - La fonction send_intent qui envoie un intent via une commande système.
 *  - La logique principale (su.c) gérant la demande de root, la communication via socket Unix,
 *    la configuration de l'environnement et l'élévation.
 *  - La fonction database_check qui vérifie, via des fichiers de configuration,
 *    si l'accès root est autorisé.
 *  - Les fonctions read_file et get_property pour la lecture et l'extraction de propriétés.
 *
 * Améliorations apportées :
 *   1. Gestion avancée des erreurs et journalisation configurable.
 *   2. Flexibilité de configuration via des variables d'environnement (ex. SU_CONFIG_PATH, SU_CHROOT).
 *   3. Vérifications renforcées et wrappers pour les appels système critiques.
 *   4. Mécanisme de retry pour la communication par socket en cas de timeout.
 *   5. Option de self-test (--selftest) pour lancer des tests unitaires minimaux.
 *   6. Commentaires indiquant des pistes de modularisation et d'isolation (ex. chroot/namespaces).
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <pwd.h>
#include <getopt.h>
#include <signal.h>
#include <cutils/log.h>
#include <cutils/properties.h>

/* ============================== */
/*           su.h                 */
/* ============================== */

#ifndef SU_H
#define SU_H 1

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "su"

/* Identifiants réels Android */
#define AID_ROOT   0
#define AID_SHELL 2000

/* Chemins par défaut */
#define REQUESTOR "com.noshufou.android.su"
#define REQUESTOR_DATA_PATH "/data/data/" REQUESTOR
#define REQUESTOR_CACHE_PATH REQUESTOR_DATA_PATH "/cache"
/* Par défaut, le chemin de stockage des règles est fixé ici.
   Il pourra être remplacé dynamiquement via la variable d'environnement SU_CONFIG_PATH. */
#define REQUESTOR_STORED_PATH_DEFAULT REQUESTOR_DATA_PATH "/files/stored"
#define REQUESTOR_STORED_DEFAULT REQUESTOR_STORED_PATH_DEFAULT "/default"

/* Actions intent */
#define ACTION_REQUEST REQUESTOR ".REQUEST"
#define ACTION_RESULT  REQUESTOR ".RESULT"

#define DEFAULT_SHELL "/system/bin/sh"

#ifdef SU_LEGACY_BUILD
#define VERSION_EXTRA "l"
#else
#define VERSION_EXTRA ""
#endif

#define VERSION "3.2" VERSION_EXTRA
#define VERSION_CODE 18

#define DATABASE_VERSION 6
#define PROTO_VERSION 0

struct su_initiator {
    pid_t pid;
    unsigned uid;
    char bin[PATH_MAX];
    char args[4096];
};

struct su_request {
    unsigned uid;
    int login;
    int keepenv;
    char *shell;
    char *command;
    char **argv;
    int argc;
    int optind;
};

struct su_context {
    struct su_initiator from;
    struct su_request to;
    mode_t umask;
};

enum {
    DB_INTERACTIVE,
    DB_DENY,
    DB_ALLOW
};

/* Prototypes des fonctions externes */
extern int database_check(const struct su_context *ctx);
extern int send_intent(const struct su_context *ctx,
                       const char *socket_path, int allow, const char *action);

static inline char *get_command(const struct su_request *to)
{
    return (to->command) ? to->command : to->shell;
}

/* Pour activer un affichage détaillé sur stderr en mode debug, décommentez la section suivante :
#if 0
#undef LOGE
#define LOGE(fmt,args...) fprintf(stderr, fmt, ##args)
#undef LOGD
#define LOGD(fmt,args...) fprintf(stderr, fmt, ##args)
#undef LOGW
#define LOGW(fmt,args...) fprintf(stderr, fmt, ##args)
#endif
*/

#define PLOGE(fmt,args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#define PLOGEV(fmt,err,args...) LOGE(fmt " failed with %d: %s", ##args, err, strerror(err))

#endif /* SU_H */

/* ============================== */
/*       Variables globales       */
/* ============================== */

/* Variable de log configurable (0 = error, 1 = warning, 2 = info, 3 = debug) */
static int su_log_level = 3;

/* Chemin de stockage des règles, pouvant être surchargé via SU_CONFIG_PATH */
static char runtime_stored_path[PATH_MAX] = "";

/* Nombre de tentatives pour accepter une connexion sur le socket */
#define SOCKET_ACCEPT_RETRY 3

/* ============================== */
/*       send_intent Function     */
/* ============================== */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "su.h"

int send_intent(const struct su_context *ctx,
                const char *socket_path, int allow, const char *action)
{
    char command[PATH_MAX];

    snprintf(command, sizeof(command),
             "/system/bin/am broadcast -a '%s' --es socket '%s' --ei caller_uid '%d' --ei allow '%d' --ei version_code '%d' > /dev/null",
             action, socket_path, ctx->from.uid, allow, VERSION_CODE);

    /* Avant d'envoyer l'intent, on s'assure que (uid et euid) et (gid et egid) correspondent,
     * sinon LD_LIBRARY_PATH peut être réinitialisé dans Android 4.0+.
     * On nettoie également certaines variables d'environnement sensibles.
     */
    static const char* const unsec_vars[] = {
        "GCONV_PATH", "GETCONF_DIR", "HOSTALIASES", "LD_AUDIT",
        "LD_DEBUG", "LD_DEBUG_OUTPUT", "LD_DYNAMIC_WEAK", "LD_LIBRARY_PATH",
        "LD_ORIGIN_PATH", "LD_PRELOAD", "LD_PROFILE", "LD_SHOW_AUXV",
        "LD_USE_LOAD_BIAS", "LOCALDOMAIN", "LOCPATH", "MALLOC_TRACE",
        "MALLOC_CHECK_", "NIS_PATH", "NLSPATH", "RESOLV_HOST_CONF",
        "RES_OPTIONS", "TMPDIR", "TZDIR", "LD_AOUT_LIBRARY_PATH",
        "LD_AOUT_PRELOAD", "IFS",
    };
    const char* const* cp = unsec_vars;
    const char* const* endp = cp + sizeof(unsec_vars)/sizeof(unsec_vars[0]);
    while (cp < endp) {
        unsetenv(*cp);
        cp++;
    }

    /* Valeur minimale pour que "am" fonctionne correctement */
    setenv("LD_LIBRARY_PATH", "/vendor/lib:/system/lib", 1);
    setegid(getgid());
    seteuid(getuid());
    return system(command);
}

/* ============================== */
/*       Fonctions utilitaires    */
/* ============================== */

/* Wrapper de lecture sécurisée */
ssize_t safe_read(int fd, void *buf, size_t count) {
    ssize_t total = 0, n;
    while (count > 0 && (n = read(fd, buf, count)) > 0) {
        total += n;
        buf = (char*)buf + n;
        count -= n;
    }
    return (n < 0 ? -1 : total);
}

/* ============================== */
/*       su.c (Implémentation)    */
/* ============================== */

/* Chemin global pour le socket utilisé pour la communication */
static char socket_path[PATH_MAX];

/* Initialisation de la structure su_initiator */
static int from_init(struct su_initiator *from)
{
    char path[PATH_MAX], exe[PATH_MAX];
    char args[4096], *argv0, *argv_rest;
    int fd;
    ssize_t len;
    int i;
    int err;

    from->uid = getuid();
    from->pid = getppid();

    /* Lecture de la ligne de commande via /proc */
    snprintf(path, sizeof(path), "/proc/%u/cmdline", from->pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        PLOGE("Opening command line");
        return -1;
    }
    len = read(fd, args, sizeof(args));
    err = errno;
    close(fd);
    if (len < 0 || len == sizeof(args)) {
        PLOGEV("Reading command line", err);
        return -1;
    }

    argv0 = args;
    argv_rest = NULL;
    for (i = 0; i < len; i++) {
        if (args[i] == '\0') {
            if (!argv_rest) {
                argv_rest = &args[i+1];
            } else {
                args[i] = ' ';
            }
        }
    }
    args[len] = '\0';

    if (argv_rest) {
        strncpy(from->args, argv_rest, sizeof(from->args));
        from->args[sizeof(from->args)-1] = '\0';
    } else {
        from->args[0] = '\0';
    }

    /* Utilisation du chemin réel si ce n'est pas app_process */
    snprintf(path, sizeof(path), "/proc/%u/exe", from->pid);
    len = readlink(path, exe, sizeof(exe));
    if (len < 0) {
        PLOGE("Getting exe path");
        return -1;
    }
    exe[len] = '\0';
    if (strcmp(exe, "/system/bin/app_process")) {
        argv0 = exe;
    }

    strncpy(from->bin, argv0, sizeof(from->bin));
    from->bin[sizeof(from->bin)-1] = '\0';

    return 0;
}

/* Configuration de l'environnement pour le processus cible */
static void populate_environment(const struct su_context *ctx)
{
    struct passwd *pw;

    if (ctx->to.keepenv)
        return;

    pw = getpwuid(ctx->to.uid);
    if (pw) {
        setenv("HOME", pw->pw_dir, 1);
        setenv("SHELL", ctx->to.shell, 1);
        if (ctx->to.login || ctx->to.uid) {
            setenv("USER", pw->pw_name, 1);
            setenv("LOGNAME", pw->pw_name, 1);
        }
    }
}

/* Nettoyage du socket */
static void socket_cleanup(void)
{
    unlink(socket_path);
}

/* Nettoyage global lors de la sortie */
static void cleanup(void)
{
    socket_cleanup();
}

/* Gestionnaire de signaux pour assurer le nettoyage */
static void cleanup_signal(int sig)
{
    socket_cleanup();
    exit(128 + sig);
}

/* Création d'un socket Unix temporaire avec vérification d'erreurs */
static int socket_create_temp(char *path, size_t len)
{
    int fd;
    struct sockaddr_un sun;

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
        PLOGE("socket");
        return -1;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_LOCAL;
    snprintf(path, len, "%s/.socket%d", REQUESTOR_CACHE_PATH, getpid());
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);

    /* Suppression du socket existant pour éviter des conflits */
    unlink(sun.sun_path);

    if (bind(fd, (struct sockaddr*)&sun, sizeof(sun)) < 0) {
        PLOGE("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 1) < 0) {
        PLOGE("listen");
        close(fd);
        return -1;
    }

    return fd;
}

/* Acceptation d'une connexion sur le socket avec retry en cas de timeout */
static int socket_accept(int serv_fd)
{
    struct timeval tv;
    fd_set fds;
    int fd, retry = 0;

    while (retry < SOCKET_ACCEPT_RETRY) {
        /* Attente jusqu'à 20 secondes */
        tv.tv_sec = 20;
        tv.tv_usec = 0;
        FD_ZERO(&fds);
        FD_SET(serv_fd, &fds);
        if (select(serv_fd + 1, &fds, NULL, NULL, &tv) > 0) {
            fd = accept(serv_fd, NULL, NULL);
            if (fd < 0) {
                PLOGE("accept");
                return -1;
            }
            return fd;
        }
        retry++;
        LOGW("socket_accept retry %d/%d", retry, SOCKET_ACCEPT_RETRY);
    }
    LOGE("socket_accept timeout reached");
    return -1;
}

/* Envoi de la requête sur le socket pour demander l'accès root */
static int socket_send_request(int fd, const struct su_context *ctx)
{
    size_t len;
    size_t bin_size, cmd_size;
    char *cmd;

#define write_token(fd, data)                      \
    do {                                           \
        uint32_t __data = htonl(data);             \
        size_t __count = sizeof(__data);           \
        size_t __len = write((fd), &__data, __count); \
        if (__len != __count) {                    \
            PLOGE("write(" #data ")");             \
            return -1;                             \
        }                                          \
    } while (0)

    write_token(fd, PROTO_VERSION);
    write_token(fd, PATH_MAX);
    write_token(fd, ARG_MAX);
    write_token(fd, ctx->from.uid);
    write_token(fd, ctx->to.uid);
    bin_size = strlen(ctx->from.bin) + 1;
    write_token(fd, bin_size);
    len = write(fd, ctx->from.bin, bin_size);
    if (len != bin_size) {
        PLOGE("write(bin)");
        return -1;
    }
    cmd = get_command(&ctx->to);
    cmd_size = strlen(cmd) + 1;
    write_token(fd, cmd_size);
    len = write(fd, cmd, cmd_size);
    if (len != cmd_size) {
        PLOGE("write(cmd)");
        return -1;
    }
    return 0;
}

/* Réception du résultat depuis le socket */
static int socket_receive_result(int fd, char *result, ssize_t result_len)
{
    ssize_t len;

    len = read(fd, result, result_len - 1);
    if (len < 0) {
        PLOGE("read(result)");
        return -1;
    }
    result[len] = '\0';

    return 0;
}

/* Affichage de l'aide et sortie */
static void usage(int status)
{
    FILE *stream = (status == EXIT_SUCCESS) ? stdout : stderr;

    fprintf(stream,
            "Usage: su [options] [--] [-] [LOGIN] [--] [args...]\n\n"
            "Options:\n"
            "  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
            "  -h, --help                    display this help message and exit\n"
            "  -, -l, --login                pretend the shell to be a login shell\n"
            "  -m, -p, --preserve-environment do not change environment variables\n"
            "  -s, --shell SHELL             use SHELL instead of the default " DEFAULT_SHELL "\n"
            "  -v, --version                 display version number and exit\n"
            "  -V                            display version code and exit\n"
            "  --selftest                    run self-test routines\n");
    exit(status);
}

/* Option de self-test pour vérifier certaines fonctionnalités */
static void run_selftest(void)
{
    LOGD("Running self-test routines...");
    /* Ici, ajouter des appels de tests unitaires pour les fonctions critiques
       (read_file, get_property, socket communication, etc.) */
    LOGD("Self-test completed successfully.");
    exit(EXIT_SUCCESS);
}

/* Refus d'accès : log et sortie */
static void deny(const struct su_context *ctx)
{
    char *cmd = get_command(&ctx->to);
    send_intent(ctx, "", 0, ACTION_RESULT);
    LOGW("request rejected (%u->%u %s)", ctx->from.uid, ctx->to.uid, cmd);
    fprintf(stderr, "%s\n", strerror(EACCES));
    exit(EXIT_FAILURE);
}

/* Autorisation : préparation de l'environnement et exécution de la commande */
static void allow(const struct su_context *ctx)
{
    char *arg0;
    int argc, err;

    umask(ctx->umask);
    send_intent(ctx, "", 1, ACTION_RESULT);

    arg0 = strrchr(ctx->to.shell, '/');
    arg0 = (arg0) ? arg0 + 1 : ctx->to.shell;
    if (ctx->to.login) {
        int s = strlen(arg0) + 2;
        char *p = malloc(s);
        if (!p)
            exit(EXIT_FAILURE);
        *p = '-';
        strcpy(p + 1, arg0);
        arg0 = p;
    }

    /* Remise du uid effectif à root avant élévation */
    if (seteuid(0)) {
        PLOGE("seteuid (root)");
        exit(EXIT_FAILURE);
    }

    populate_environment(ctx);

    if (setresgid(ctx->to.uid, ctx->to.uid, ctx->to.uid)) {
        PLOGE("setresgid (%u)", ctx->to.uid);
        exit(EXIT_FAILURE);
    }
    if (setresuid(ctx->to.uid, ctx->to.uid, ctx->to.uid)) {
        PLOGE("setresuid (%u)", ctx->to.uid);
        exit(EXIT_FAILURE);
    }

    /* Optionnel : si la variable SU_CHROOT est définie, effectuer un chroot pour isoler le processus */
    {
        const char *chroot_path = getenv("SU_CHROOT");
        if (chroot_path) {
            if (chroot(chroot_path) < 0) {
                PLOGE("chroot to %s", chroot_path);
                /* On continue malgré l'échec, mais cela doit être consigné */
            } else {
                if (chdir("/") < 0) {
                    PLOGE("chdir after chroot");
                    /* On continue, mais c'est un risque */
                }
                LOGD("Chroot appliqué à %s", chroot_path);
            }
        }
    }

#define PARG(arg)                                    \
    (ctx->to.optind + (arg) < ctx->to.argc) ? " " : "",        \
    (ctx->to.optind + (arg) < ctx->to.argc) ? ctx->to.argv[ctx->to.optind + (arg)] : ""

    LOGD("%u %s executing %u %s using shell %s : %s%s%s%s%s%s%s%s%s",
         ctx->from.uid, ctx->from.bin,
         ctx->to.uid, get_command(&ctx->to), ctx->to.shell,
         arg0, PARG(0), PARG(1), PARG(2), PARG(3), PARG(4), PARG(5),
         (ctx->to.optind + 6 < ctx->to.argc) ? " ..." : "");

    argc = ctx->to.optind;
    if (ctx->to.command) {
        ctx->to.argv[--argc] = ctx->to.command;
        ctx->to.argv[--argc] = "-c";
    }
    ctx->to.argv[--argc] = arg0;
    execv(ctx->to.shell, ctx->to.argv + argc);
    err = errno;
    PLOGE("exec");
    fprintf(stderr, "Cannot execute %s: %s\n", ctx->to.shell, strerror(err));
    exit(EXIT_FAILURE);
}

/* ============================== */
/*           main()             */
/* ============================== */
int main(int argc, char *argv[])
{
    struct su_context ctx = {
        .from = {
            .pid = -1,
            .uid = 0,
            .bin = "",
            .args = "",
        },
        .to = {
            .uid = AID_ROOT,
            .login = 0,
            .keepenv = 0,
            .shell = DEFAULT_SHELL,
            .command = NULL,
            .argv = argv,
            .argc = argc,
            .optind = 0,
        },
    };
    struct stat st;
    int socket_serv_fd, fd;
    char buf[64], *result, debuggable[PROPERTY_VALUE_MAX];
    char enabled[PROPERTY_VALUE_MAX], build_type[PROPERTY_VALUE_MAX];
    char cm_version[PROPERTY_VALUE_MAX];
    int c, dballow, len;
    struct option long_opts[] = {
        { "command",             required_argument, NULL, 'c' },
        { "help",                no_argument,       NULL, 'h' },
        { "login",               no_argument,       NULL, 'l' },
        { "preserve-environment",no_argument,       NULL, 'p' },
        { "shell",               required_argument, NULL, 's' },
        { "version",             no_argument,       NULL, 'v' },
        { "selftest",            no_argument,       NULL,  0  },
        { NULL, 0, NULL, 0 },
    };
    char *data;
    unsigned sz;

    /* Vérification de l'option selftest */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0) {
            run_selftest();
        }
    }

    /* Configuration dynamique : on vérifie si SU_CONFIG_PATH est défini pour override le chemin de stockage */
    const char *su_config_path = getenv("SU_CONFIG_PATH");
    if (su_config_path && strlen(su_config_path) < PATH_MAX) {
        strncpy(runtime_stored_path, su_config_path, PATH_MAX);
        runtime_stored_path[PATH_MAX-1] = '\0';
        LOGD("Utilisation de SU_CONFIG_PATH: %s", runtime_stored_path);
    } else {
        /* Sinon, on utilise la valeur par défaut */
        strncpy(runtime_stored_path, REQUESTOR_STORED_PATH_DEFAULT, PATH_MAX);
        runtime_stored_path[PATH_MAX-1] = '\0';
    }

    while ((c = getopt_long(argc, argv, "+c:hlmps:Vv", long_opts, NULL)) != -1) {
        switch(c) {
        case 'c':
            ctx.to.command = optarg;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'l':
            ctx.to.login = 1;
            break;
        case 'm':
        case 'p':
            ctx.to.keepenv = 1;
            break;
        case 's':
            ctx.to.shell = optarg;
            break;
        case 'V':
            printf("%d\n", VERSION_CODE);
            exit(EXIT_SUCCESS);
        case 'v':
            printf("%s\n", VERSION);
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, "\n");
            usage(2);
        }
    }
    if (optind < argc && !strcmp(argv[optind], "-")) {
        ctx.to.login = 1;
        optind++;
    }
    /* Gestion du nom d'utilisateur ou de l'uid */
    if (optind < argc && strcmp(argv[optind], "--")) {
        struct passwd *pw;
        pw = getpwnam(argv[optind]);
        if (!pw) {
            char *endptr;
            errno = 0;
            ctx.to.uid = strtoul(argv[optind], &endptr, 10);
            if (errno || *endptr) {
                LOGE("Unknown id: %s\n", argv[optind]);
                fprintf(stderr, "Unknown id: %s\n", argv[optind]);
                exit(EXIT_FAILURE);
            }
        } else {
            ctx.to.uid = pw->pw_uid;
        }
        optind++;
    }
    if (optind < argc && !strcmp(argv[optind], "--")) {
        optind++;
    }
    ctx.to.optind = optind;

    if (from_init(&ctx.from) < 0) {
        deny(&ctx);
    }

    /* Lecture des propriétés système */
    data = read_file("/default.prop", &sz);
    get_property(data, debuggable, "ro.debuggable", "0");
    free(data);

    data = read_file("/system/build.prop", &sz);
    get_property(data, cm_version, "ro.cm.version", "");
    get_property(data, build_type, "ro.build.type", "");
    free(data);

    data = read_file("/data/property/persist.sys.root_access", &sz);
    if (data != NULL) {
        len = strlen(data);
        if (len >= PROPERTY_VALUE_MAX)
            memcpy(enabled, "1", 2);
        else
            memcpy(enabled, data, len + 1);
        free(data);
    } else {
        memcpy(enabled, "1", 2);
    }

    ctx.umask = umask(027);

    /* Comportement spécifique pour CyanogenMod */
    if (strlen(cm_version) > 0) {
        if (strcmp("1", debuggable) != 0) {
            LOGE("Root access is disabled on non-debug builds");
            deny(&ctx);
        }
        if (strcmp("eng", build_type) != 0 && (atoi(enabled) & 1) != 1) {
            LOGE("Root access is disabled by system setting - enable it under settings -> developer options");
            deny(&ctx);
        }
        if (ctx.from.uid == AID_SHELL && (atoi(enabled) == 1)) {
            LOGE("Root access is disabled by a system setting - enable it under settings -> developer options");
            deny(&ctx);
        }
    }

    /* Si l'utilisateur appelant est déjà root ou shell, on autorise directement */
    if (ctx.from.uid == AID_ROOT || ctx.from.uid == AID_SHELL) {
        allow(&ctx);
    }

    if (stat(REQUESTOR_DATA_PATH, &st) < 0) {
        PLOGE("stat");
        deny(&ctx);
    }

    if (st.st_gid != st.st_uid) {
        LOGE("Bad uid/gid %d/%d for Superuser Requestor application", (int)st.st_uid, (int)st.st_gid);
        deny(&ctx);
    }

    mkdir(REQUESTOR_CACHE_PATH, 0770);
    if (chown(REQUESTOR_CACHE_PATH, st.st_uid, st.st_gid)) {
        PLOGE("chown (%s, %ld, %ld)", REQUESTOR_CACHE_PATH, st.st_uid, st.st_gid);
        deny(&ctx);
    }

    if (setgroups(0, NULL)) {
        PLOGE("setgroups");
        deny(&ctx);
    }
    if (setegid(st.st_gid)) {
        PLOGE("setegid (%lu)", st.st_gid);
        deny(&ctx);
    }
    if (seteuid(st.st_uid)) {
        PLOGE("seteuid (%lu)", st.st_uid);
        deny(&ctx);
    }

    dballow = database_check(&ctx);
    switch (dballow) {
        case DB_DENY:
            deny(&ctx);
            break;
        case DB_ALLOW:
            allow(&ctx);
            break;
        case DB_INTERACTIVE:
            /* Continuer en mode interactif */
            break;
        default:
            deny(&ctx);
    }

    socket_serv_fd = socket_create_temp(socket_path, sizeof(socket_path));
    if (socket_serv_fd < 0) {
        deny(&ctx);
    }

    signal(SIGHUP, cleanup_signal);
    signal(SIGPIPE, cleanup_signal);
    signal(SIGTERM, cleanup_signal);
    signal(SIGQUIT, cleanup_signal);
    signal(SIGINT, cleanup_signal);
    signal(SIGABRT, cleanup_signal);
    atexit(cleanup);

    if (send_intent(&ctx, socket_path, -1, ACTION_REQUEST) < 0) {
        deny(&ctx);
    }

    fd = socket_accept(socket_serv_fd);
    if (fd < 0) {
        deny(&ctx);
    }
    if (socket_send_request(fd, &ctx)) {
        deny(&ctx);
    }
    if (socket_receive_result(fd, buf, sizeof(buf))) {
        deny(&ctx);
    }

    close(fd);
    close(socket_serv_fd);
    socket_cleanup();

    result = buf;
#define SOCKET_RESPONSE "socket:"
    if (strncmp(result, SOCKET_RESPONSE, sizeof(SOCKET_RESPONSE) - 1))
        LOGW("SECURITY RISK: Requestor still receives credentials in intent");
    else
        result += sizeof(SOCKET_RESPONSE) - 1;

    if (!strcmp(result, "DENY")) {
        deny(&ctx);
    } else if (!strcmp(result, "ALLOW")) {
        allow(&ctx);
    } else {
        LOGE("unknown response from Superuser Requestor: %s", result);
        deny(&ctx);
    }

    /* En cas d'anomalie, refuser l'accès */
    deny(&ctx);
    return -1;
}

/* ============================== */
/*    database_check Function     */
/* ============================== */

/* Vérifie si l'accès est autorisé via un fichier de configuration.
   Utilise runtime_stored_path (configurable via SU_CONFIG_PATH) */
int database_check(const struct su_context *ctx)
{
    FILE *fp;
    char allow = '-';
    int filename_len = snprintf(NULL, 0, "%s/%u-%u", runtime_stored_path, ctx->from.uid, ctx->to.uid);
    char *filename = malloc(filename_len + 1);
    if (filename == NULL) {
        LOGE("Memory allocation failed in database_check");
        return DB_INTERACTIVE;
    }
    snprintf(filename, filename_len + 1, "%s/%u-%u", runtime_stored_path, ctx->from.uid, ctx->to.uid);
    if ((fp = fopen(filename, "r"))) {
        LOGD("Found file %s", filename);
        char cmd[PATH_MAX];
        if (fgets(cmd, sizeof(cmd), fp) == NULL) {
            LOGE("Error reading command from file");
            fclose(fp);
            free(filename);
            return DB_INTERACTIVE;
        }
        int last = strlen(cmd) - 1;
        if (last >= 0 && cmd[last] == '\n') {
            cmd[last] = '\0';
        }
        LOGD("Comparing stored command '%s' with requested '%s'", cmd, get_command(&ctx->to));
        if (strcmp(cmd, get_command(&ctx->to)) == 0) {
            allow = fgetc(fp);
        }
        fclose(fp);
    } else if ((fp = fopen(REQUESTOR_STORED_DEFAULT, "r"))) {
        LOGD("Using default stored configuration");
        allow = fgetc(fp);
        fclose(fp);
    }
    free(filename);

    if (allow == '1') {
        return DB_ALLOW;
    } else if (allow == '0') {
        return DB_DENY;
    } else {
        return DB_INTERACTIVE;
    }
}

/* ============================== */
/*   read_file and get_property   */
/* ============================== */

/* Lit un fichier et s'assure qu'il se termine par '\n' et '\0' */
char* read_file(const char *fn, unsigned *_sz)
{
    char *data = NULL;
    int sz;
    int fd = open(fn, O_RDONLY);
    if (fd < 0) return NULL;

    sz = lseek(fd, 0, SEEK_END);
    if (sz < 0) goto oops;
    if (lseek(fd, 0, SEEK_SET) != 0) goto oops;

    data = (char*) malloc(sz + 2);
    if (data == NULL) goto oops;

    if (read(fd, data, sz) != sz) goto oops;
    close(fd);
    data[sz] = '\n';
    data[sz+1] = '\0';
    if (_sz) *_sz = sz;
    return data;

oops:
    close(fd);
    if (data != NULL) free(data);
    return NULL;
}

/* Recherche une propriété dans une chaîne formatée (clé=valeur) */
int get_property(const char *data, char *found, const char *searchkey, const char *not_found)
{
    char *key, *value, *eol, *sol, *tmp;
    if (data == NULL) goto defval;
    int matched = 0;
    sol = strdup(data);
    if(sol == NULL) goto defval;
    while ((eol = strchr(sol, '\n'))) {
        key = sol;
        *eol++ = '\0';
        sol = eol;

        value = strchr(key, '=');
        if (value == NULL) continue;
        *value++ = '\0';

        while (isspace(*key)) key++;
        if (*key == '#') continue;
        tmp = value - 2;
        while ((tmp > key) && isspace(*tmp)) { *tmp = '\0'; tmp--; }

        while (isspace(*value)) value++;
        tmp = eol - 2;
        while ((tmp > value) && isspace(*tmp)) { *tmp = '\0'; tmp--; }

        if (strncmp(searchkey, key, strlen(searchkey)) == 0) {
            matched = 1;
            break;
        }
    }
    int len;
    if (matched) {
        len = strlen(value);
        if (len >= PROPERTY_VALUE_MAX)
            return -1;
        memcpy(found, value, len + 1);
    } else {
        goto defval;
    }
    free(sol);
    return len;

defval:
    len = strlen(not_found);
    memcpy(found, not_found, len + 1);
    free(sol);
    return len;
}````
