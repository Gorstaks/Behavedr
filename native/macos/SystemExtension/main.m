/*
 * Behavedr Endpoint Security host binary (0.3.4)
 *
 * This is a real ES client process suitable for packaging into a System Extension
 * bundle *once* Apple enrollment + OSSystemExtensionRequest wiring is added by
 * release engineering. Today it runs as an elevated ES host daemon that publishes
 * JSONL events for operators / future agent XPC.
 *
 * Not claimed: App Store install, automatic SE activation, or agent consumption.
 *
 * Build: ./build.sh
 * Env: BEHAVEDR_ES_AUTH=1, BEHAVEDR_ES_EVENTS_PATH=...
 */

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#include <libproc.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RING 4096
#define KIND_LEN 32
#define NAME_LEN 64
#define PATH_LEN 512

typedef struct {
    char kind[KIND_LEN];
    int pid;
    char name[NAME_LEN];
    char path[PATH_LEN];
} se_event;

static es_client_t *g_client = NULL;
static volatile sig_atomic_t g_stop = 0;
static se_event g_ring[RING];
static atomic_uint g_head = 0;
static atomic_uint g_tail = 0;
static pthread_mutex_t g_file_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_auth_mode = 0;
static FILE *g_events_fp = NULL;
static char g_events_path[512] = "/var/run/behavedr/es.events";

static void on_sig(int s) { (void)s; g_stop = 1; }

/* Staging-path denylist - rename-resistant; never deny /opt/behavedr */
static int path_is_exec_denylisted(const char *path)
{
    if (!path || !path[0]) return 0;
    if (strncmp(path, "/opt/behavedr/", 14) == 0) return 0;
    if (strncmp(path, "/tmp/", 5) == 0) return 1;
    if (strncmp(path, "/private/tmp/", 13) == 0) return 1;
    if (strncmp(path, "/var/tmp/", 9) == 0) return 1;
    if (strncmp(path, "/dev/shm/", 9) == 0) return 1;
    if (strstr(path, "/Users/Shared/") != NULL) return 1;
    return 0;
}

static void copy_token(char *dst, size_t dstlen, es_string_token_t tok)
{
    dst[0] = '\0';
    if (!tok.data || tok.length == 0) return;
    size_t n = tok.length < dstlen - 1 ? tok.length : dstlen - 1;
    memcpy(dst, tok.data, n);
    dst[n] = '\0';
}

static void enqueue(const char *kind, int pid, const char *name, const char *path)
{
    uint32_t head = atomic_load_explicit(&g_head, memory_order_relaxed);
    uint32_t next = (head + 1u) % RING;
    uint32_t tail = atomic_load_explicit(&g_tail, memory_order_acquire);
    if (next == tail)
        return; /* drop newest */

    se_event *e = &g_ring[head];
    memset(e, 0, sizeof(*e));
    if (kind) strncpy(e->kind, kind, KIND_LEN - 1);
    e->pid = pid;
    if (name) strncpy(e->name, name, NAME_LEN - 1);
    if (path) strncpy(e->path, path, PATH_LEN - 1);
    atomic_store_explicit(&g_head, next, memory_order_release);
}

static void json_escape(const char *in, char *out, size_t outlen)
{
    size_t j = 0;
    if (!in) { out[0] = '\0'; return; }
    for (size_t i = 0; in[i] && j + 2 < outlen; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = c;
        } else if ((unsigned char)c >= 0x20) {
            out[j++] = c;
        }
    }
    out[j] = '\0';
}

static void write_jsonl(const se_event *e)
{
    char ek[KIND_LEN * 2], en[NAME_LEN * 2], ep[PATH_LEN * 2];
    json_escape(e->kind, ek, sizeof(ek));
    json_escape(e->name, en, sizeof(en));
    json_escape(e->path, ep, sizeof(ep));

    pthread_mutex_lock(&g_file_mu);
    if (g_events_fp) {
        fprintf(g_events_fp,
                "{\"ts\":%lld,\"kind\":\"%s\",\"pid\":%d,\"name\":\"%s\",\"path\":\"%s\"}\n",
                (long long)time(NULL), ek, e->pid, en, ep);
        fflush(g_events_fp);
    }
    pthread_mutex_unlock(&g_file_mu);
}

static void handle_msg(es_client_t *client, const es_message_t *msg)
{
    if (!msg || !msg->process) return;

    pid_t pid = audit_token_to_pid(msg->process->audit_token);
    char name[NAME_LEN] = {0};
    if (proc_name(pid, name, sizeof(name)) <= 0)
        snprintf(name, sizeof(name), "pid-%d", (int)pid);

    const char *kind = "event";
    char pathbuf[PATH_LEN] = {0};
    int is_auth_exec = 0;

    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
        is_auth_exec = 1;
        kind = "auth_exec";
        if (msg->event.exec.target && msg->event.exec.target->executable)
            copy_token(pathbuf, sizeof(pathbuf), msg->event.exec.target->executable->path);
        break;
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        kind = "exec";
        if (msg->event.exec.target && msg->event.exec.target->executable)
            copy_token(pathbuf, sizeof(pathbuf), msg->event.exec.target->executable->path);
        break;
    case ES_EVENT_TYPE_NOTIFY_FORK:
        kind = "fork";
        break;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        kind = "exit";
        break;
    case ES_EVENT_TYPE_NOTIFY_OPEN:
        kind = "open";
        if (msg->event.open.file)
            copy_token(pathbuf, sizeof(pathbuf), msg->event.open.file->path);
        break;
    case ES_EVENT_TYPE_NOTIFY_CREATE:
        kind = "create";
        break;
    case ES_EVENT_TYPE_NOTIFY_WRITE:
        kind = "write";
        break;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
        kind = "rename";
        break;
    default:
        break;
    }

    enqueue(kind, (int)pid, name, pathbuf);

    if (is_auth_exec) {
        es_auth_result_t result = (g_auth_mode && path_is_exec_denylisted(pathbuf))
            ? ES_AUTH_RESULT_DENY
            : ES_AUTH_RESULT_ALLOW;
        es_respond_auth_result(client, msg, result, false);
        if (result == ES_AUTH_RESULT_DENY)
            enqueue("auth_denied", (int)pid, name, pathbuf);
    }
}

static int open_events_file(void)
{
    const char *env = getenv("BEHAVEDR_ES_EVENTS_PATH");
    if (env && env[0])
        snprintf(g_events_path, sizeof(g_events_path), "%s", env);

    char dir[512];
    snprintf(dir, sizeof(dir), "%s", g_events_path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir, 0750);
    }

    g_events_fp = fopen(g_events_path, "a");
    if (!g_events_fp) {
        fprintf(stderr, "[BehavedrES] cannot open %s - logging to stderr only\n", g_events_path);
        return -1;
    }
    fchmod(fileno(g_events_fp), 0640);
    fprintf(stderr, "[BehavedrES] events -> %s\n", g_events_path);
    return 0;
}

static void *publisher_thread(void *arg)
{
    (void)arg;
    while (!g_stop) {
        uint32_t tail = atomic_load_explicit(&g_tail, memory_order_relaxed);
        uint32_t head = atomic_load_explicit(&g_head, memory_order_acquire);
        if (tail == head) {
            usleep(25000);
            continue;
        }
        se_event e = g_ring[tail];
        atomic_store_explicit(&g_tail, (tail + 1u) % RING, memory_order_release);
        write_jsonl(&e);
        fprintf(stderr, "[BehavedrES] %s pid=%d name=%s\n", e.kind, e.pid, e.name);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    const char *auth = getenv("BEHAVEDR_ES_AUTH");
    g_auth_mode = (auth && strcmp(auth, "1") == 0) ? 1 : 0;

    open_events_file();

    es_new_client_result_t res = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handle_msg(c, m);
    });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "[BehavedrES] es_new_client failed: %d\n", (int)res);
        return 1;
    }

    es_mute_path(g_client, "/opt/behavedr/", ES_MUTE_PATH_TYPE_PREFIX);

    es_event_type_t events[16];
    int n = 0;
    events[n++] = ES_EVENT_TYPE_NOTIFY_EXEC;
    events[n++] = ES_EVENT_TYPE_NOTIFY_FORK;
    events[n++] = ES_EVENT_TYPE_NOTIFY_EXIT;
    events[n++] = ES_EVENT_TYPE_NOTIFY_OPEN;
    events[n++] = ES_EVENT_TYPE_NOTIFY_CREATE;
    events[n++] = ES_EVENT_TYPE_NOTIFY_WRITE;
    events[n++] = ES_EVENT_TYPE_NOTIFY_RENAME;
    if (g_auth_mode) {
        events[n++] = ES_EVENT_TYPE_AUTH_EXEC;
        fprintf(stderr, "[BehavedrES] AUTH_EXEC denylist enabled\n");
    }

    if (es_subscribe(g_client, events, n) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "[BehavedrES] es_subscribe failed\n");
        es_delete_client(g_client);
        return 2;
    }

    pthread_t thr;
    pthread_create(&thr, NULL, publisher_thread, NULL);

    fprintf(stderr, "[BehavedrES] subscribed events=%d - running (ES host binary)\n", n);
    while (!g_stop)
        sleep(1);

    pthread_join(thr, NULL);
    es_delete_client(g_client);
    if (g_events_fp) fclose(g_events_fp);
    return 0;
}
