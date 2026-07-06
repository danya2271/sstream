#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <picoquic.h>
#include <picoquic_packet_loop.h>
#include <picosocks.h>
#ifdef BUILD_LOGLIB
#include <autoqlog.h>
#endif
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <assert.h>
#include <strings.h>
#include <picoquic_internal.h>
#include <slipstream_sockloop.h>

#include "lua-resty-base-encoding-base32.h"
#include "picoquic_config.h"
#include "picoquic_logger.h"
#include "slipstream.h"
#include "slipstream_inline_dots.h"
#include "../include/slipstream_server_cc.h"
#include "slipstream_slot.h"
#include "slipstream_utils.h"
#include "SPCDNS/src/dns.h"
#include "SPCDNS/src/mappings.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

volatile sig_atomic_t should_shutdown = 0;

void server_sighandler(int signum) {
    DBG_PRINTF("Signal %d received", signum);
    should_shutdown = 1;
}

char* server_domain_name = NULL;
size_t server_domain_name_len = 0;
char* server_domain_suffix = NULL;
size_t server_domain_suffix_len = 0;
bool server_domain_wildcard = false;
static bool server_stream_logs_enabled = false;
static bool server_packed_queries_enabled = false;

#define SERVER_STREAM_LOG(...) \
    do { \
        if (server_stream_logs_enabled) { \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while (0)

static socklen_t slipstream_sockaddr_len(const struct sockaddr_storage* addr) {
    if (addr->ss_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    }
    if (addr->ss_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return sizeof(struct sockaddr_storage);
}

static const char* slipstream_format_sockaddr(const struct sockaddr_storage* addr, char* buf, size_t buf_len) {
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    int ret = getnameinfo((const struct sockaddr*)addr, slipstream_sockaddr_len(addr),
                          host, sizeof(host), service, sizeof(service),
                          NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret != 0) {
        snprintf(buf, buf_len, "unknown");
    } else if (addr->ss_family == AF_INET6) {
        snprintf(buf, buf_len, "[%s]:%s", host, service);
    } else {
        snprintf(buf, buf_len, "%s:%s", host, service);
    }
    return buf;
}

static const char* slipstream_server_event_name(picoquic_call_back_event_t event) {
    switch (event) {
    case picoquic_callback_stateless_reset:
        return "stateless reset";
    case picoquic_callback_close:
        return "connection close";
    case picoquic_callback_application_close:
        return "application close";
    default:
        return "connection event";
    }
}

/* --- FIXED: Added ref_count to manage memory safety across threads --- */
typedef struct st_slipstream_server_stream_ctx_t {
    struct st_slipstream_server_stream_ctx_t* next_stream;
    struct st_slipstream_server_stream_ctx_t* previous_stream;
    int fd;
    int pipefd[2];
    uint64_t stream_id;
    volatile sig_atomic_t set_active;
    volatile int poller_active;
    volatile int summary_logged;
    uint64_t bytes_to_upstream;
    uint64_t bytes_from_upstream;
    int ref_count; /* Reference counter for thread safety */
} slipstream_server_stream_ctx_t;

typedef struct st_slipstream_server_ctx_t {
    picoquic_cnx_t* cnx;
    slipstream_server_stream_ctx_t* first_stream;
    picoquic_network_thread_ctx_t* thread_ctx;
    struct sockaddr_storage upstream_addr;
    struct st_slipstream_server_ctx_t* prev_ctx;
    struct st_slipstream_server_ctx_t* next_ctx;
} slipstream_server_ctx_t;

static void slipstream_server_send_query_pack_capability(picoquic_cnx_t* cnx) {
    const uint8_t control[] = SLIPSTREAM_QUERY_PACK_CONTROL;
    const uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 1);
    (void)picoquic_add_to_stream(cnx, stream_id, control, sizeof(control) - 1, 1);
}

/* Helper to retain context (increment ref count) */
void slipstream_stream_retain(slipstream_server_stream_ctx_t* ctx) {
    __sync_add_and_fetch(&ctx->ref_count, 1);
}

/* Helper to release context (decrement ref count and free if 0) */
void slipstream_stream_release(slipstream_server_stream_ctx_t* ctx) {
    if (__sync_sub_and_fetch(&ctx->ref_count, 1) == 0) {
        // Only verify FDs are closed, but memory is freed here.
        if (ctx->fd != -1) close(ctx->fd);
        if (ctx->pipefd[0] != -1) close(ctx->pipefd[0]);
        if (ctx->pipefd[1] != -1) close(ctx->pipefd[1]);
        free(ctx);
        // DBG_PRINTF("Stream context freed from memory", NULL);
    }
}

static void slipstream_server_log_stream_summary(slipstream_server_stream_ctx_t* stream_ctx,
                                                 const char* reason) {
    if (!__sync_bool_compare_and_swap(&stream_ctx->summary_logged, 0, 1)) {
        return;
    }

    SERVER_STREAM_LOG(
        "Server stream closed: id=%llu fd=%d reason=%s client_to_upstream=%llu upstream_to_client=%llu\n",
        (unsigned long long)stream_ctx->stream_id,
        stream_ctx->fd,
        reason,
        (unsigned long long)stream_ctx->bytes_to_upstream,
        (unsigned long long)stream_ctx->bytes_from_upstream);
}

ssize_t server_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, size_t* segment_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr) {
    *dest_buf = NULL;
    assert(segment_len == NULL || *segment_len == 0 || *segment_len == src_buf_len);
    slot_t* slot = (slot_t*) slot_p;

#ifdef NOENCODE
    *dest_buf = malloc(src_buf_len);
    memcpy((void*)*dest_buf, src_buf, src_buf_len);
    memcpy(peer_addr, &slot->peer_addr, sizeof(struct sockaddr_storage));
    memcpy(local_addr, &slot->local_addr, sizeof(struct sockaddr_storage));
    return src_buf_len;
#endif

    dns_query_t *query = (dns_query_t *) slot->dns_decoded;
    dns_txt_t answer_txt;
    dns_answer_t edns = {0};
    edns.opt.name = ".";
    edns.opt.type = RR_OPT;
    edns.opt.class = CLASS_UNKNOWN;
    edns.opt.ttl = 0;
    edns.opt.udp_payload = 1232;

    dns_query_t response = {0};
    response.id = query->id;
    response.query = false;
    response.opcode = OP_QUERY;
    response.aa = true;
    response.rd = query->rd;
    response.cd = query->cd;
    response.rcode = slot->error;
    response.qdcount = 1;
    response.questions = query->questions;

    if (src_buf_len > 0) {
        const dns_question_t *question = &query->questions[0];
        answer_txt.name = question->name;
        answer_txt.type = question->type;
        answer_txt.class = question->class;
        answer_txt.ttl = 60;
        answer_txt.text = (char *)src_buf;
        answer_txt.len = src_buf_len;

        response.ancount = 1;
        response.answers = (dns_answer_t *)&answer_txt;
    } else {
        if (slot->error == RCODE_OKAY) {
            response.rcode = RCODE_NAME_ERROR;
        }
    }

    response.arcount = 1;
    response.additional = &edns;

    dns_packet_t* packet = malloc(MAX_UDP_PACKET_SIZE);
    size_t packet_len = MAX_UDP_PACKET_SIZE;
    dns_rcode_t rc = dns_encode(packet, &packet_len, &response);
    if (rc != RCODE_OKAY) {
        free(packet);
        DBG_PRINTF("dns_encode() = (%d) %s", rc, dns_rcode_text(rc));
        return -1;
    }
    *dest_buf = (unsigned char*)packet;

    memcpy(peer_addr, &slot->peer_addr, sizeof(struct sockaddr_storage));
    memcpy(local_addr, &slot->local_addr, sizeof(struct sockaddr_storage));

    return packet_len;
}

static ssize_t slipstream_server_encoded_prefix_len(const char* qname) {
    size_t q_len = strlen(qname);
    size_t q_end = q_len;
    if (q_end > 0 && qname[q_end - 1] == '.') {
        q_end--;
    }

    if (server_domain_suffix == NULL || q_end < server_domain_suffix_len + 2) {
        return -1;
    }

    const size_t suffix_start = q_end - server_domain_suffix_len;
    if (suffix_start == 0 || qname[suffix_start - 1] != '.' ||
        strncasecmp(qname + suffix_start, server_domain_suffix, server_domain_suffix_len) != 0) {
        return -1;
    }

    if (!server_domain_wildcard) {
        return (ssize_t)(suffix_start - 1);
    }

    const size_t dot_before_suffix = suffix_start - 1;
    size_t wildcard_start = dot_before_suffix;
    while (wildcard_start > 0 && qname[wildcard_start - 1] != '.') {
        wildcard_start--;
    }

    if (wildcard_start == 0 || wildcard_start == dot_before_suffix) {
        return -1;
    }

    return (ssize_t)(wildcard_start - 1);
}

ssize_t server_decode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage *peer_addr, struct sockaddr_storage *local_addr) {
    *dest_buf = NULL;
    slot_t* slot = slot_p;

    memcpy(&slot->peer_addr, peer_addr, sizeof(struct sockaddr_storage));
    sockaddr_dummy(peer_addr);
    memcpy(&slot->local_addr, local_addr, sizeof(struct sockaddr_storage));

#ifdef NODECODE
    *dest_buf = malloc(src_buf_len);
    memcpy((void*)*dest_buf, src_buf, src_buf_len);
    return src_buf_len;
#endif

    size_t packet_len = DNS_DECODEBUF_4K * sizeof(dns_decoded_t);
    dns_decoded_t* packet = slot->dns_decoded;
    const dns_rcode_t rc = dns_decode(packet, &packet_len, (const dns_packet_t*) src_buf, src_buf_len);
    if (rc != RCODE_OKAY) {
        DBG_PRINTF("dns_decode() = (%d) %s", rc, dns_rcode_text(rc));
        slot->error = RCODE_FORMAT_ERROR;
        return 0;
    }

    const dns_query_t *query = (dns_query_t*) packet;
    if (!query->query) {
        DBG_PRINTF("dns record is not a query", NULL);
        slot->error = RCODE_FORMAT_ERROR;
        return 0;
    }

    if (query->qdcount != 1) {
        DBG_PRINTF("dns record should contain exactly one query", NULL);
        slot->error = RCODE_FORMAT_ERROR;
        return 0;
    }

    const dns_question_t *question = &query->questions[0];
    if (question->type != RR_TXT) {
        slot->error = RCODE_NAME_ERROR;
        return 0;
    }

    const ssize_t data_len = slipstream_server_encoded_prefix_len(question->name);
    if (data_len <= 0) {
        slot->error = RCODE_NAME_ERROR;
        return 0;
    }

    char data_buf[data_len + 1];
    memcpy(data_buf, question->name, data_len);
    data_buf[data_len] = '\0';
    const size_t encoded_len = slipstream_inline_undotify(data_buf, data_len);

    char* decoded_buf = malloc(encoded_len);
    const size_t decoded_len = b32_decode(decoded_buf, data_buf, encoded_len, false);
    if (decoded_len == (size_t) -1) {
        free(decoded_buf);
        DBG_PRINTF("error decoding base32: %lu", decoded_len);
        slot->error = RCODE_SERVER_FAILURE;
        return 0;
    }

    *dest_buf = decoded_buf;
    return decoded_len;
}

slipstream_server_stream_ctx_t* slipstream_server_create_stream_ctx(slipstream_server_ctx_t* server_ctx,
                                                                    uint64_t stream_id) {
    slipstream_server_stream_ctx_t* stream_ctx = malloc(sizeof(slipstream_server_stream_ctx_t));

    if (stream_ctx == NULL) {
        DBG_PRINTF("Memory Error, cannot create stream", NULL);
        return NULL;
    }

    memset(stream_ctx, 0, sizeof(slipstream_server_stream_ctx_t));
    stream_ctx->stream_id = stream_id;
    stream_ctx->ref_count = 1;

    if (pipe(stream_ctx->pipefd) < 0) {
        perror("pipe() failed");
        free(stream_ctx);
        return NULL;
    }

    int socket_family = server_ctx->upstream_addr.ss_family;
    if (socket_family != AF_INET && socket_family != AF_INET6) {
        socket_family = AF_INET;
    }

    int sock_fd = socket(socket_family, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket() failed");
        close(stream_ctx->pipefd[0]);
        close(stream_ctx->pipefd[1]);
        free(stream_ctx);
        return NULL;
    }

    struct timeval tv;
    tv.tv_sec = 1800;
    tv.tv_usec = 0;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) {
        perror("setsockopt failed");
    }
    if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv) < 0) {
        perror("setsockopt failed");
    }

    stream_ctx->fd = sock_fd;

    if (server_ctx->first_stream == NULL) {
        server_ctx->first_stream = stream_ctx;
    } else {
        stream_ctx->next_stream = server_ctx->first_stream;
        stream_ctx->next_stream->previous_stream = stream_ctx;
        server_ctx->first_stream = stream_ctx;
    }

    SERVER_STREAM_LOG("Server stream opened: id=%llu fd=%d\n",
                      (unsigned long long)stream_id, sock_fd);

    return stream_ctx;
}

/* FIXED: This function now unlinks the stream but does NOT necessarily free memory.
   It closes FDs to signal threads to stop, then releases its reference. */
static void slipstream_server_free_stream_context(slipstream_server_ctx_t* server_ctx,
                                             slipstream_server_stream_ctx_t* stream_ctx,
                                             const char* reason) {
    slipstream_server_log_stream_summary(stream_ctx, reason);

    // 1. Unlink from the list so main thread ignores it from now on
    if (stream_ctx->previous_stream != NULL) {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }
    if (stream_ctx->next_stream != NULL) {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }
    if (server_ctx->first_stream == stream_ctx) {
        server_ctx->first_stream = stream_ctx->next_stream;
    }

    if (server_ctx->cnx != NULL && stream_ctx->stream_id != UINT64_MAX) {
        picoquic_unlink_app_stream_ctx(server_ctx->cnx, stream_ctx->stream_id);
        stream_ctx->stream_id = UINT64_MAX;
    }

    // 2. Close FDs immediately to interrupt any blocking calls in threads
    if (stream_ctx->fd != -1) {
        close(stream_ctx->fd);
        stream_ctx->fd = -1;
    }

    if (stream_ctx->pipefd[0] != -1) {
        close(stream_ctx->pipefd[0]);
        stream_ctx->pipefd[0] = -1;
    }
    if (stream_ctx->pipefd[1] != -1) {
        close(stream_ctx->pipefd[1]);
        stream_ctx->pipefd[1] = -1;
    }

    // 3. Release main thread's reference.
    slipstream_stream_release(stream_ctx);
}

static void slipstream_server_free_context(slipstream_server_ctx_t* server_ctx) {
    slipstream_server_stream_ctx_t* stream_ctx;
    while ((stream_ctx = server_ctx->first_stream) != NULL) {
        slipstream_server_free_stream_context(server_ctx, stream_ctx, "connection close");
    }
    if (server_ctx->prev_ctx) {
        server_ctx->prev_ctx->next_ctx = server_ctx->next_ctx;
    }
    if (server_ctx->next_ctx) {
        server_ctx->next_ctx->prev_ctx = server_ctx->prev_ctx;
    }
    free(server_ctx);
}

void slipstream_server_mark_active_pass(slipstream_server_ctx_t* server_ctx) {
    slipstream_server_stream_ctx_t* stream_ctx = server_ctx->first_stream;
    while (stream_ctx != NULL) {
        if (stream_ctx->set_active) {
            stream_ctx->set_active = 0;
            // Only mark active if FD is still valid (not closed)
            if (stream_ctx->fd != -1) {
                DBG_PRINTF("[stream_id=%d][fd=%d] activate: stream", stream_ctx->stream_id, stream_ctx->fd);
                picoquic_mark_active_stream(server_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
            }
        }
        stream_ctx = stream_ctx->next_stream;
    }
}

int slipstream_server_sockloop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
                                   void* callback_ctx, void* callback_arg) {
    slipstream_server_ctx_t* default_ctx = callback_ctx;
    switch (cb_mode) {
    case picoquic_packet_loop_wake_up:
        if (callback_ctx == NULL) return 0;
        slipstream_server_ctx_t* server_ctx = default_ctx->next_ctx;
        while (server_ctx != NULL) {
            slipstream_server_mark_active_pass(server_ctx);
            server_ctx = server_ctx->next_ctx;
        }
        break;
    case picoquic_packet_loop_before_select:
        if (should_shutdown) {
            picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic);
            bool has_unclosed = false;
            while (cnx != NULL) {
                if (cnx->cnx_state != picoquic_state_disconnected) {
                    has_unclosed = true;
                }
                picoquic_close(cnx, 0);
                if (cnx->cnx_state == picoquic_state_draining) {
                    picoquic_connection_disconnect(cnx);
                }
                cnx = picoquic_get_next_cnx(cnx);
            }
            if (!has_unclosed) {
                DBG_PRINTF("All connections closed, shutting down.", NULL);
                return -1;
            }
        }
    default:
        break;
    }
    return 0;
}

typedef struct st_slipstream_server_poller_args {
    int fd;
    picoquic_cnx_t* cnx;
    slipstream_server_ctx_t* server_ctx;
    slipstream_server_stream_ctx_t* stream_ctx;
} slipstream_server_poller_args;

static void* slipstream_server_poller(void* arg);

static void slipstream_server_arm_poller(picoquic_cnx_t* cnx,
                                         slipstream_server_ctx_t* server_ctx,
                                         slipstream_server_stream_ctx_t* stream_ctx) {
    if (!__sync_bool_compare_and_swap(&stream_ctx->poller_active, 0, 1)) {
        return;
    }

    slipstream_server_poller_args* args = malloc(sizeof(slipstream_server_poller_args));
    if (args == NULL) {
        __sync_lock_release(&stream_ctx->poller_active);
        return;
    }
    args->fd = stream_ctx->fd;
    args->cnx = cnx;
    args->server_ctx = server_ctx;
    args->stream_ctx = stream_ctx;

    slipstream_stream_retain(stream_ctx);
    pthread_t thread;
    if (pthread_create(&thread, NULL, slipstream_server_poller, args) != 0) {
        free(args);
        slipstream_stream_release(stream_ctx);
        __sync_lock_release(&stream_ctx->poller_active);
        return;
    }

    pthread_detach(thread);
}

static void* slipstream_server_poller(void* arg) {
    slipstream_server_poller_args* args = arg;
    slipstream_server_stream_ctx_t* stream_ctx = args->stream_ctx;

    while (1) {
        struct pollfd fds;
        fds.fd = args->fd;
        fds.events = POLLIN;
        fds.revents = 0;

        int ret = poll(&fds, 1, 1000);

        // If poll fails (likely because FD was closed by main thread), exit
        if (ret < 0) {
            // perror("poll() failed");
            break;
        }
        if (ret == 0) continue;

        if (stream_ctx->fd != -1) {
            stream_ctx->set_active = 1;
        }
        ret = picoquic_wake_up_network_thread(args->server_ctx->thread_ctx);
        if (ret != 0) {
            DBG_PRINTF("poll: could not wake up network thread, ret = %d", ret);
        }
        break;
    }

    // Release context reference held by this thread
    __sync_lock_release(&stream_ctx->poller_active);
    slipstream_stream_release(stream_ctx);
    free(args);
    pthread_exit(NULL);
}

static void slipstream_server_close_pipe_write_end(slipstream_server_stream_ctx_t* stream_ctx) {
    if (stream_ctx->pipefd[1] != -1) {
        close(stream_ctx->pipefd[1]);
        stream_ctx->pipefd[1] = -1;
    }
}

static void slipstream_server_wake_thread(picoquic_network_thread_ctx_t* thread_ctx,
                                          slipstream_server_stream_ctx_t* stream_ctx,
                                          const char* reason) {
    if (thread_ctx == NULL) {
        return;
    }

    stream_ctx->set_active = 1;
    int wake_ret = picoquic_wake_up_network_thread(thread_ctx);
    if (wake_ret != 0) {
        fprintf(stderr, "Server stream wakeup failed after %s: stream=%llu ret=%d\n",
                reason, (unsigned long long)stream_ctx->stream_id, wake_ret);
    }
}

static void slipstream_server_wake_stream(slipstream_server_ctx_t* server_ctx,
                                          slipstream_server_stream_ctx_t* stream_ctx,
                                          const char* reason) {
    slipstream_server_wake_thread(server_ctx == NULL ? NULL : server_ctx->thread_ctx, stream_ctx, reason);
}

typedef struct st_slipstream_io_copy_args {
    int pipe;
    int socket;
    uint64_t stream_id;
    picoquic_network_thread_ctx_t* thread_ctx;
    struct sockaddr_storage upstream_addr;
    slipstream_server_stream_ctx_t* stream_ctx;
} slipstream_io_copy_args;

static int slipstream_write_all(int fd, const uint8_t* bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t bytes_written = write(fd, bytes + offset, length - offset);
        if (bytes_written > 0) {
            offset += (size_t)bytes_written;
            continue;
        }
        if (bytes_written < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

void* slipstream_io_copy(void* arg) {
    char buffer[65535];
    slipstream_io_copy_args* args = arg;
    int pipe = args->pipe;
    int socket = args->socket;
    uint64_t stream_id = args->stream_id;
    slipstream_server_stream_ctx_t* stream_ctx = args->stream_ctx;

    if (connect(socket, (struct sockaddr*)&args->upstream_addr,
                slipstream_sockaddr_len(&args->upstream_addr)) < 0) {
        // Connection failed, close stream
        char upstream_text[NI_MAXHOST + NI_MAXSERV + 8];
        fprintf(stderr, "Server upstream connect failed: stream=%llu target=%s error=%s (%d)\n",
                (unsigned long long)stream_id,
                slipstream_format_sockaddr(&args->upstream_addr, upstream_text, sizeof(upstream_text)),
                strerror(errno), errno);
        slipstream_server_wake_thread(args->thread_ctx, stream_ctx, "upstream connect failure");
        slipstream_stream_release(stream_ctx);
        free(args);
        return NULL;
    }

    DBG_PRINTF("[%lu:%d] setup pipe done", stream_ctx->stream_id, stream_ctx->fd);
    char upstream_text[NI_MAXHOST + NI_MAXSERV + 8];
    SERVER_STREAM_LOG("Server upstream connected: stream=%llu target=%s fd=%d\n",
                      (unsigned long long)stream_id,
                      slipstream_format_sockaddr(&args->upstream_addr, upstream_text, sizeof(upstream_text)),
                      socket);
    stream_ctx->set_active = 1;
    int ret = picoquic_wake_up_network_thread(args->thread_ctx);
    if (ret != 0) {
        fprintf(stderr, "Server upstream wakeup failed: stream=%llu ret=%d\n",
                (unsigned long long)stream_id, ret);
    }
    DBG_PRINTF("[stream_id=%d][fd=%d] wakeup", stream_ctx->stream_id, socket);

    bool input_fin = false;
    bool upstream_send_failed = false;
    while (1) {
        // Read from pipe (data coming from QUIC)
        ssize_t bytes_read = read(pipe, buffer, sizeof(buffer));

        if (bytes_read == 0) {
            input_fin = true;
            break;
        }
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        char *p = buffer;
        ssize_t remaining = bytes_read;

        while (remaining > 0) {
            // Write to TCP socket (backend)
            // If socket is closed by main thread, this will fail with EBADF
            ssize_t bytes_written = send(socket, p, remaining, MSG_NOSIGNAL);
            if (bytes_written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                fprintf(stderr, "Server upstream send failed: stream=%llu error=%s (%d)\n",
                        (unsigned long long)stream_id, strerror(errno), errno);
                upstream_send_failed = true;
                slipstream_server_wake_thread(args->thread_ctx, stream_ctx, "upstream send failure");
                goto cleanup; // Exit loop on error
            }
            __sync_add_and_fetch(&stream_ctx->bytes_to_upstream, (uint64_t)bytes_written);
            remaining -= bytes_written;
            p += bytes_written;
        }
    }

cleanup:
    if (input_fin && stream_ctx->fd != -1) {
        (void)shutdown(socket, SHUT_WR);
        slipstream_server_wake_thread(args->thread_ctx, stream_ctx, "client stream fin");
    } else if (!upstream_send_failed && stream_ctx->fd != -1) {
        slipstream_server_wake_thread(args->thread_ctx, stream_ctx, "upstream copy stop");
    }
    SERVER_STREAM_LOG("Server upstream copy stopped: stream=%llu fd=%d\n",
                      (unsigned long long)stream_id, socket);
    // Release context reference held by this thread
    slipstream_stream_release(stream_ctx);
    free(args);
    return NULL;
}

int slipstream_server_callback(picoquic_cnx_t* cnx,
                               uint64_t stream_id, uint8_t* bytes, size_t length,
                               picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx) {
    int ret = 0;
    slipstream_server_ctx_t* server_ctx = (slipstream_server_ctx_t*)callback_ctx;
    slipstream_server_stream_ctx_t* stream_ctx = (slipstream_server_stream_ctx_t*)v_stream_ctx;

    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        server_ctx = (slipstream_server_ctx_t*)malloc(sizeof(slipstream_server_ctx_t));
        if (server_ctx == NULL) {
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        slipstream_server_ctx_t* d_ctx = picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
        if (d_ctx != NULL) memcpy(server_ctx, d_ctx, sizeof(slipstream_server_ctx_t));
        else memset(server_ctx, 0, sizeof(slipstream_server_ctx_t));
        server_ctx->cnx = cnx;
        picoquic_set_callback(cnx, slipstream_server_callback, server_ctx);
        if (d_ctx->next_ctx != NULL) d_ctx->next_ctx->prev_ctx = server_ctx;
        server_ctx->next_ctx = d_ctx->next_ctx;
        server_ctx->prev_ctx = d_ctx;
        d_ctx->next_ctx = server_ctx;
        struct sockaddr* peer_addr = NULL;
        picoquic_get_peer_addr(cnx, &peer_addr);
        char peer_text[NI_MAXHOST + NI_MAXSERV + 8];
        if (peer_addr != NULL) {
            struct sockaddr_storage peer_storage = {0};
            if (peer_addr->sa_family == AF_INET) {
                memcpy(&peer_storage, peer_addr, sizeof(struct sockaddr_in));
            } else if (peer_addr->sa_family == AF_INET6) {
                memcpy(&peer_storage, peer_addr, sizeof(struct sockaddr_in6));
            }
            fprintf(stderr, "Server QUIC connection created: peer=%s\n",
                    slipstream_format_sockaddr(&peer_storage, peer_text, sizeof(peer_text)));
        } else {
            fprintf(stderr, "Server QUIC connection created: peer=unknown\n");
        }
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (stream_ctx == NULL) {
            stream_ctx = slipstream_server_create_stream_ctx(server_ctx, stream_id);
            if (stream_ctx == NULL || picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
                if (stream_ctx != NULL) {
                    slipstream_server_free_stream_context(server_ctx, stream_ctx, "stream setup failure");
                }
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }

            slipstream_io_copy_args* args = malloc(sizeof(slipstream_io_copy_args));
            args->pipe = stream_ctx->pipefd[0];
            args->socket = stream_ctx->fd;
            args->stream_id = stream_ctx->stream_id;
            args->thread_ctx = server_ctx->thread_ctx;
            memcpy(&args->upstream_addr, &server_ctx->upstream_addr, sizeof(args->upstream_addr));
            args->stream_ctx = stream_ctx;

            // Retain context for the new thread
            slipstream_stream_retain(stream_ctx);

            pthread_t thread;
            if (pthread_create(&thread, NULL, slipstream_io_copy, args) != 0) {
                perror("pthread_create() failed for thread1");
                free(args);
                slipstream_stream_release(stream_ctx); // Release if thread fail
            } else {
                pthread_detach(thread);
            }
        }

        if (length > 0) {
            // Check if pipe is still valid
            if (stream_ctx->pipefd[1] != -1) {
                if (slipstream_write_all(stream_ctx->pipefd[1], bytes, length) != 0) {
                    // Pipe broken
                    fprintf(stderr, "Server stream pipe write failed: id=%llu fd=%d error=%s (%d)\n",
                            (unsigned long long)stream_id, stream_ctx->fd, strerror(errno), errno);
                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                    return 0;
                }
            }
        }
        if (fin_or_event == picoquic_callback_stream_fin) {
            SERVER_STREAM_LOG("Server stream finished: id=%llu fd=%d\n",
                              (unsigned long long)stream_id, stream_ctx == NULL ? -1 : stream_ctx->fd);
            if (stream_ctx != NULL) {
                slipstream_server_close_pipe_write_end(stream_ctx);
                slipstream_server_wake_stream(server_ctx, stream_ctx, "client stream fin");
            }
        }
        break;
    case picoquic_callback_stop_sending:
        picoquic_reset_stream(cnx, stream_id, 0);
    case picoquic_callback_stream_reset:
        if (stream_ctx != NULL) {
            SERVER_STREAM_LOG("Server stream reset: id=%llu fd=%d\n",
                              (unsigned long long)stream_id, stream_ctx->fd);
            slipstream_server_free_stream_context(server_ctx, stream_ctx, "stream reset");
            picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close:
    case picoquic_callback_application_close: {
        fprintf(stderr, "Server QUIC %s received\n", slipstream_server_event_name(fin_or_event));
        picoquic_network_thread_ctx_t* thread_ctx = server_ctx == NULL ? NULL : server_ctx->thread_ctx;
        if (server_ctx != NULL) {
            slipstream_server_free_context(server_ctx);
        }
        picoquic_set_callback(cnx, NULL, NULL);
        picoquic_close(cnx, 0);
        if (thread_ctx != NULL) {
            picoquic_wake_up_network_thread(thread_ctx);
        }
        break;
    }
    case picoquic_callback_prepare_to_send:
        if (stream_ctx != NULL && stream_ctx->fd != -1) {
            int length_available;
            ret = ioctl(stream_ctx->fd, FIONREAD, &length_available);
            if (ret < 0) {
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                break;
            }
            ret = 0;

            size_t length_to_read = MIN((size_t)length, (size_t)length_available);
            if (length_to_read == 0) {
                char a;
                errno = 0;
                ssize_t bytes_read = recv(stream_ctx->fd, &a, 1, MSG_PEEK | MSG_DONTWAIT);
                if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
                    slipstream_server_arm_poller(cnx, server_ctx, stream_ctx);
                    return 0;
                }
                if (bytes_read == 0) {
                    SERVER_STREAM_LOG("Server upstream closed connection: stream=%llu fd=%d\n",
                                      (unsigned long long)stream_id, stream_ctx->fd);
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 1, 0);
                    slipstream_server_free_stream_context(server_ctx, stream_ctx, "upstream eof");
                    return 0;
                }
                if (bytes_read > 0) {
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 1);
                    break;
                }
                if (bytes_read < 0) {
                    fprintf(stderr, "Server upstream peek failed: stream=%llu fd=%d error=%s (%d)\n",
                            (unsigned long long)stream_id, stream_ctx->fd, strerror(errno), errno);
                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                }
                return 0;
            }

            uint8_t stack_buffer[PICOQUIC_MAX_PACKET_SIZE];
            if (length_to_read > sizeof(stack_buffer)) {
                length_to_read = sizeof(stack_buffer);
            }
            ssize_t bytes_read = recv(stream_ctx->fd, stack_buffer, length_to_read, MSG_DONTWAIT);
            if (bytes_read == 0) {
                SERVER_STREAM_LOG("Server upstream closed while reading: stream=%llu fd=%d\n",
                                  (unsigned long long)stream_id, stream_ctx->fd);
                (void)picoquic_provide_stream_data_buffer(bytes, 0, 1, 0);
                slipstream_server_free_stream_context(server_ctx, stream_ctx, "upstream eof");
                return 0;
            }
            if (bytes_read < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
                    slipstream_server_arm_poller(cnx, server_ctx, stream_ctx);
                    return 0;
                }
                fprintf(stderr, "Server upstream read failed: stream=%llu fd=%d error=%s (%d)\n",
                        (unsigned long long)stream_id, stream_ctx->fd, strerror(errno), errno);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
            __sync_add_and_fetch(&stream_ctx->bytes_from_upstream, (uint64_t)bytes_read);
            uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, (size_t)bytes_read, 0, 1);
            if (buffer == NULL) break;
            memcpy(buffer, stack_buffer, (size_t)bytes_read);
        }
        break;
    case picoquic_callback_almost_ready:
        fprintf(stderr, "Server QUIC connection almost ready\n");
        break;
    case picoquic_callback_ready:
        fprintf(stderr, "Server QUIC connection ready\n");
        if (server_packed_queries_enabled) {
            slipstream_server_send_query_pack_capability(cnx);
        }
        break;
    default:
        break;
    }
    return ret;
}

int picoquic_slipstream_server(int server_port, bool listen_ipv6, int mtu, const char* server_cert, const char* server_key,
                               struct sockaddr_storage* target_address, const char* domain_name) {
    int ret = 0;
    uint64_t current_time = 0;
    slipstream_server_ctx_t default_context = {0};
    server_stream_logs_enabled = getenv("SLIPSTREAM_SERVER_STREAM_LOGS") != NULL;
    server_packed_queries_enabled = getenv("SLIPSTREAM_PACKED_QUERIES") != NULL;
    if (mtu > SLIPSTREAM_SERVER_MTU_MAX) {
        fprintf(stderr, "Server MTU %d is too large for DNS TXT responses; using %d\n", mtu, SLIPSTREAM_SERVER_MTU_MAX);
        mtu = SLIPSTREAM_SERVER_MTU_MAX;
    }
    const int initial_mtu = mtu < SLIPSTREAM_SERVER_MTU_INITIAL ? mtu : SLIPSTREAM_SERVER_MTU_INITIAL;
    const int mtu_probe_ceiling = mtu + (listen_ipv6 ? 48 : 28);

    memcpy(&default_context.upstream_addr, target_address, sizeof(struct sockaddr_storage));

    if (strncmp(domain_name, "*.", 2) == 0 && domain_name[2] == '\0') {
        fprintf(stderr, "Wildcard domain must include a suffix, for example *.meowda.space\n");
        return -1;
    }

    server_domain_name = strdup(domain_name);
    server_domain_name_len = strlen(domain_name);
    server_domain_wildcard = strncmp(server_domain_name, "*.", 2) == 0;
    server_domain_suffix = server_domain_wildcard ? server_domain_name + 2 : server_domain_name;
    server_domain_suffix_len = strlen(server_domain_suffix);

    char upstream_text[NI_MAXHOST + NI_MAXSERV + 8];
    fprintf(stderr,
            "Server starting: listen=%s:%d domain=%s%s target=%s mtu-initial=%d mtu-max=%d cid-len=%d pmtud=required packed-queries=%s cert=%s key=%s\n",
            listen_ipv6 ? "[::]" : "0.0.0.0", server_port, domain_name,
            server_domain_wildcard ? " (wildcard one-label subdomains)" : "",
            slipstream_format_sockaddr(target_address, upstream_text, sizeof(upstream_text)),
            initial_mtu, mtu, SLIPSTREAM_CONNECTION_ID_LEN,
            server_packed_queries_enabled ? "on" : "off", server_cert, server_key);

    picoquic_quic_config_t config;
    picoquic_config_init(&config);
    config.nb_connections = 65535;
    config.server_cert_file = server_cert;
    config.server_key_file = server_key;
#ifdef BUILD_LOGLIB
    config.qlog_dir = SLIPSTREAM_QLOG_DIR;
#endif
    config.server_port = server_port;
    config.mtu_max = mtu_probe_ceiling;
    config.initial_send_mtu_ipv4 = initial_mtu;
    config.initial_send_mtu_ipv6 = initial_mtu;
    config.cnx_id_length = SLIPSTREAM_CONNECTION_ID_LEN;
    config.multipath_option = 1;
    config.use_long_log = 0;
    config.do_preemptive_repeat = 1;
    config.disable_port_blocking = 1;
    config.enable_sslkeylog = getenv("SSLKEYLOGFILE") != NULL;
    config.alpn = SLIPSTREAM_ALPN;

    current_time = picoquic_current_time();
    picoquic_quic_t* quic = picoquic_create_and_configure(&config, slipstream_server_callback, &default_context, current_time, NULL);
    if (quic == NULL) return -1;

    picoquic_set_cookie_mode(quic, 0);
    picoquic_set_default_priority(quic, 2);
#ifdef BUILD_LOGLIB
    picoquic_set_qlog(quic, config.qlog_dir);
    debug_printf_push_stream(stderr);
#endif
    picoquic_set_key_log_file_from_env(quic);
    picoquic_set_default_congestion_algorithm(quic, slipstream_server_cc_algorithm);
    picoquic_set_default_pmtud_policy(quic, picoquic_pmtud_required);

    picoquic_packet_loop_param_t param = {0};
    if (listen_ipv6) {
        param.local_af = AF_INET6;
    } else {
        param.local_af = AF_INET;
    }
    param.local_port = server_port;
    param.do_not_use_gso = 1;
    param.is_client = 0;
    param.decode = server_decode;
    param.encode = server_encode;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.quic = quic;
    thread_ctx.param = &param;
    thread_ctx.loop_callback = slipstream_server_sockloop_callback;
    thread_ctx.loop_callback_ctx = &default_context;

    picoquic_open_network_wake_up(&thread_ctx, &ret);
    default_context.thread_ctx = &thread_ctx;

    signal(SIGTERM, server_sighandler);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
    slipstream_packet_loop(&thread_ctx);
    ret = thread_ctx.return_code;

    picoquic_free(quic);
    return ret;
}
