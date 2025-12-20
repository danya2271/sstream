#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_packet_loop.h>
#include <picosocks.h>
#ifdef BUILD_LOGLIB
#include <autoqlog.h>
#endif
#include <pthread.h>
#include <stdbool.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <assert.h>
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

volatile sig_atomic_t should_shutdown = 0;

void server_sighandler(int signum) {
    DBG_PRINTF("Signal %d received", signum);
    should_shutdown = 1;
}

char* server_domain_name = NULL;
size_t server_domain_name_len = 0;

/* --- FIXED: Added ref_count to manage memory safety across threads --- */
typedef struct st_slipstream_server_stream_ctx_t {
    struct st_slipstream_server_stream_ctx_t* next_stream;
    struct st_slipstream_server_stream_ctx_t* previous_stream;
    int fd;
    int pipefd[2];
    uint64_t stream_id;
    volatile sig_atomic_t set_active;
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
        return EXIT_FAILURE;
    }
    *dest_buf = (unsigned char*)packet;

    memcpy(peer_addr, &slot->peer_addr, sizeof(struct sockaddr_storage));
    memcpy(local_addr, &slot->local_addr, sizeof(struct sockaddr_storage));

    return packet_len;
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
        return -1;
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

    size_t q_len = strlen(question->name);
    if (q_len < server_domain_name_len + 2) {
        slot->error = RCODE_NAME_ERROR;
        return 0;
    }

    const ssize_t data_len = q_len - server_domain_name_len - 2;
    if (data_len <= 0) {
        slot->error = RCODE_NAME_ERROR;
        return 0;
    }

    char data_buf[data_len];
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

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
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

    return stream_ctx;
}

/* FIXED: This function now unlinks the stream but does NOT necessarily free memory.
   It closes FDs to signal threads to stop, then releases its reference. */
static void slipstream_server_free_stream_context(slipstream_server_ctx_t* server_ctx,
                                             slipstream_server_stream_ctx_t* stream_ctx) {
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
        slipstream_server_free_stream_context(server_ctx, stream_ctx);
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

void* slipstream_server_poller(void* arg) {
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

        stream_ctx->set_active = 1;
        ret = picoquic_wake_up_network_thread(args->server_ctx->thread_ctx);
        if (ret != 0) {
            DBG_PRINTF("poll: could not wake up network thread, ret = %d", ret);
        }
        break;
    }

    // Release context reference held by this thread
    slipstream_stream_release(stream_ctx);
    free(args);
    pthread_exit(NULL);
}

typedef struct st_slipstream_io_copy_args {
    int pipe;
    int socket;
    picoquic_cnx_t* cnx;
    slipstream_server_ctx_t* server_ctx;
    slipstream_server_stream_ctx_t* stream_ctx;
} slipstream_io_copy_args;

void* slipstream_io_copy(void* arg) {
    char buffer[65535];
    slipstream_io_copy_args* args = arg;
    int pipe = args->pipe;
    int socket = args->socket;
    slipstream_server_ctx_t* server_ctx = args->server_ctx;
    slipstream_server_stream_ctx_t* stream_ctx = args->stream_ctx;

    if (connect(socket, (struct sockaddr*)&server_ctx->upstream_addr, sizeof(server_ctx->upstream_addr)) < 0) {
        // Connection failed, close stream
        // perror("connect() failed");
        slipstream_stream_release(stream_ctx);
        free(args);
        return NULL;
    }

    DBG_PRINTF("[%lu:%d] setup pipe done", stream_ctx->stream_id, stream_ctx->fd);
    stream_ctx->set_active = 1;
    int ret = picoquic_wake_up_network_thread(args->server_ctx->thread_ctx);
    DBG_PRINTF("[stream_id=%d][fd=%d] wakeup", stream_ctx->stream_id, socket);

    while (1) {
        // Read from pipe (data coming from QUIC)
        ssize_t bytes_read = read(pipe, buffer, sizeof(buffer));

        // If read fails or returns 0, it means the main thread closed the pipe
        if (bytes_read <= 0) {
            break;
        }

        char *p = buffer;
        ssize_t remaining = bytes_read;

        while (remaining > 0) {
            // Write to TCP socket (backend)
            // If socket is closed by main thread, this will fail with EBADF
            ssize_t bytes_written = send(socket, p, remaining, 0);
            if (bytes_written < 0) {
                // perror("send failed");
                goto cleanup; // Exit loop on error
            }
            remaining -= bytes_written;
            p += bytes_written;
        }
    }

cleanup:
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
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (stream_ctx == NULL) {
            stream_ctx = slipstream_server_create_stream_ctx(server_ctx, stream_id);
            if (stream_ctx == NULL || picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
                if(stream_ctx) free(stream_ctx);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }

            slipstream_io_copy_args* args = malloc(sizeof(slipstream_io_copy_args));
            args->pipe = stream_ctx->pipefd[0];
            args->socket = stream_ctx->fd;
            args->cnx = cnx;
            args->server_ctx = server_ctx;
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
                ssize_t bytes_sent = write(stream_ctx->pipefd[1], bytes, length);
                if (bytes_sent < 0) {
                    // Pipe broken
                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                    return 0;
                }
            }
        }
        if (fin_or_event == picoquic_callback_stream_fin) {
            /* Close local sock */
            if (stream_ctx->fd != -1) { close(stream_ctx->fd); stream_ctx->fd = -1; }
            picoquic_unlink_app_stream_ctx(cnx, stream_id);
        }
        break;
    case picoquic_callback_stop_sending:
        picoquic_reset_stream(cnx, stream_id, 0);
    case picoquic_callback_stream_reset:
        if (stream_ctx != NULL) {
            slipstream_server_free_stream_context(server_ctx, stream_ctx);
            picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close:
    case picoquic_callback_application_close:
        if (server_ctx != NULL) {
            slipstream_server_free_context(server_ctx);
        }
        picoquic_set_callback(cnx, NULL, NULL);
        picoquic_close(cnx, 0);
        picoquic_wake_up_network_thread(server_ctx->thread_ctx);
        break;
    case picoquic_callback_prepare_to_send:
        if (stream_ctx != NULL && stream_ctx->fd != -1) {
            int length_available;
            ret = ioctl(stream_ctx->fd, FIONREAD, &length_available);
            if (ret < 0) {
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                break;
            }
            ret = 0;

            int length_to_read = MIN(length, length_available);
            if (length_to_read == 0) {
                char a;
                ssize_t bytes_read = recv(stream_ctx->fd, &a, 1, MSG_PEEK | MSG_DONTWAIT);
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);

                    slipstream_server_poller_args* args = malloc(sizeof(slipstream_server_poller_args));
                    args->fd = stream_ctx->fd;
                    args->cnx = cnx;
                    args->server_ctx = server_ctx;
                    args->stream_ctx = stream_ctx;

                    // Retain for poller thread
                    slipstream_stream_retain(stream_ctx);

                    pthread_t thread;
                    if (pthread_create(&thread, NULL, slipstream_server_poller, args) != 0) {
                        free(args);
                        slipstream_stream_release(stream_ctx);
                    } else {
                        pthread_detach(thread);
                    }
                }
                if (bytes_read == 0) {
                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                    return 0;
                }
                if (bytes_read > 0) {
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 1);
                    break;
                }
                return 0;
            }

            uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, length_to_read, 0, 1);
            if (buffer == NULL) break;

            ssize_t bytes_read = recv(stream_ctx->fd, buffer, length_to_read, MSG_DONTWAIT);
            if (bytes_read == 0) {
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                return 0;
            }
            if (bytes_read < 0) {
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
        }
        break;
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        break;
    default:
        break;
    }
    return ret;
}

int picoquic_slipstream_server(int server_port, int mtu, const char* server_cert, const char* server_key,
                               struct sockaddr_storage* target_address, const char* domain_name) {
    int ret = 0;
    uint64_t current_time = 0;
    slipstream_server_ctx_t default_context = {0};

    memcpy(&default_context.upstream_addr, target_address, sizeof(struct sockaddr_storage));

    server_domain_name = strdup(domain_name);
    server_domain_name_len = strlen(domain_name);

    picoquic_quic_config_t config;
    picoquic_config_init(&config);
    config.nb_connections = 65535;
    config.server_cert_file = server_cert;
    config.server_key_file = server_key;
#ifdef BUILD_LOGLIB
    config.qlog_dir = SLIPSTREAM_QLOG_DIR;
#endif
    config.server_port = server_port;
    config.mtu_max = mtu;
    config.initial_send_mtu_ipv4 = mtu;
    config.initial_send_mtu_ipv6 = mtu;
    config.multipath_option = 1;
    config.use_long_log = 1;
    config.do_preemptive_repeat = 1;
    config.disable_port_blocking = 1;
    config.enable_sslkeylog = 1;
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

    picoquic_packet_loop_param_t param = {0};
    param.local_af = AF_INET;
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
    slipstream_packet_loop(&thread_ctx);
    ret = thread_ctx.return_code;

    picoquic_free(quic);
    return ret;
}
