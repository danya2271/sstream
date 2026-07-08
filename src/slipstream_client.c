// ReSharper disable CppDFAUnreachableCode
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_packet_loop.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#ifdef BUILD_LOGLIB
#include <autoqlog.h>
#endif
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <picoquic_internal.h>
#include <pthread.h>
#include <signal.h>
#include <slipstream_sockloop.h>
#include <stdbool.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>

#include "lua-resty-base-encoding-base32.h"
#include "picoquic_config.h"
#include "slipstream.h"
#include "slipstream_inline_dots.h"
#include "slipstream_utils.h"
#include "SPCDNS/src/dns.h"
#include "SPCDNS/src/mappings.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

volatile sig_atomic_t should_shutdown = 0;

void client_sighandler(int signum) {
    DBG_PRINTF("Signal %d received", signum);
    should_shutdown = 1;
}

#define SLIPSTREAM_ACTIVE_POLL_INTERVAL_US 20000
#define SLIPSTREAM_RESOLVER_CONNECT_TIMEOUT_US 10000000
#define SLIPSTREAM_RESOLVER_PROBE_INITIAL_DELAY_US 1000000
#define SLIPSTREAM_RESOLVER_PROBE_MAX_DELAY_US 30000000
#define SLIPSTREAM_RESOLVER_SELECTION_MIN_US 1000000
#define SLIPSTREAM_RESOLVER_SELECTION_TIMEOUT_US 5000000
#define SLIPSTREAM_RESOLVER_SELECTION_RTT_DELTA_US 1000
#define SLIPSTREAM_RESOLVER_PATH_ID_UNKNOWN UINT64_MAX
#define SLIPSTREAM_RESOLVER_HEALTH_MIN_SENT_DELTA 32
#define SLIPSTREAM_RESOLVER_BAD_LOSS_PERMILLE 200
#define SLIPSTREAM_RESOLVER_UNHEALTHY_COOLDOWN_US 15000000
#define SLIPSTREAM_RESOLVER_SWITCH_SCORE_MARGIN_US 250000
#define SLIPSTREAM_RESOLVER_LOSS_SCORE_US_PER_PERMILLE 4000
#define SLIPSTREAM_RESOLVER_CWIN_COLLAPSED_BYTES 1500
#define SLIPSTREAM_RESOLVER_CWIN_COLLAPSE_PENALTY_US 500000
#define SLIPSTREAM_RESOLVER_QUALITY_LOG_INTERVAL_US 2000000
#define SLIPSTREAM_RESOLVER_MTU_MIN_BYTES 80
#define SLIPSTREAM_RESOLVER_MTU_BAD_LOSS_PERMILLE 100
#define SLIPSTREAM_RESOLVER_MTU_RECOVERY_LOSS_PERMILLE 20
#define SLIPSTREAM_RESOLVER_MTU_ADJUST_INTERVAL_US 5000000
#define SLIPSTREAM_RESOLVER_MTU_STEP_MIN_BYTES 12
#define SLIPSTREAM_RESOLVER_MTU_GROW_STEP_BYTES 8
#define SLIPSTREAM_RESOLVER_MTU_GOOD_WINDOWS_TO_GROW 5
#define SLIPSTREAM_RESOLVER_HEALTH_CHECK_INTERVAL_US 1000000
#define SLIPSTREAM_RESOLVER_RESELECTION_INTERVAL_US 5000000
#define SLIPSTREAM_RESOLVER_SAMPLE_STALE_US 12000000
#define SLIPSTREAM_RESOLVER_FAILOVER_MIN_INTERVAL_US 8000000
#define SLIPSTREAM_RESOLVER_ACTIVE_BAD_LOSS_PERMILLE 200
#define SLIPSTREAM_RESOLVER_ACTIVE_BAD_WINDOWS 4

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

static const char* slipstream_client_event_name(picoquic_call_back_event_t event) {
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

static void slipstream_client_log_path_event(picoquic_cnx_t* cnx, uint64_t unique_path_id, const char* event_name) {
    struct sockaddr_storage peer_addr = {0};
    struct sockaddr_storage local_addr = {0};
    char peer_text[NI_MAXHOST + NI_MAXSERV + 8];
    char local_text[NI_MAXHOST + NI_MAXSERV + 8];
    picoquic_path_quality_t quality = {0};

    if (picoquic_get_path_addr(cnx, unique_path_id, 2, &peer_addr) != 0) {
        peer_addr.ss_family = 0;
    }
    if (picoquic_get_path_addr(cnx, unique_path_id, 1, &local_addr) != 0) {
        local_addr.ss_family = 0;
    }
    (void)picoquic_get_path_quality(cnx, unique_path_id, &quality);

    fprintf(stderr,
            "Client resolver path %s: id=%llu peer=%s local=%s rtt=%.1fms sent=%llu lost=%llu cwin=%llu\n",
            event_name,
            (unsigned long long)unique_path_id,
            peer_addr.ss_family == 0 ? "unknown" : slipstream_format_sockaddr(&peer_addr, peer_text, sizeof(peer_text)),
            local_addr.ss_family == 0 ? "unknown" : slipstream_format_sockaddr(&local_addr, local_text, sizeof(local_text)),
            (double)quality.rtt / 1000.0,
            (unsigned long long)quality.sent,
            (unsigned long long)quality.lost,
            (unsigned long long)quality.cwin);
}


typedef struct st_slipstream_client_stream_ctx_t {
    struct st_slipstream_client_stream_ctx_t* next_stream;
    struct st_slipstream_client_stream_ctx_t* previous_stream;
    int fd;
    uint64_t stream_id;
    volatile sig_atomic_t set_active;
    volatile int poller_active;
    int ref_count;
} slipstream_client_stream_ctx_t;

typedef struct st_slipstream_client_ctx_t {
    picoquic_cnx_t* cnx;
    slipstream_client_stream_ctx_t* first_stream;
    picoquic_network_thread_ctx_t* thread_ctx;
    struct st_address_t* server_addresses;
    size_t server_address_count;
    bool ready;
    bool closed;
    bool reconnect_pending;
    int listen_sock;
    size_t keep_alive_interval;
    uint64_t reconnect_at;
    uint64_t reconnect_delay;
    size_t active_resolver_index;
    size_t next_resolver_index;
    uint64_t connect_started_at;
    uint64_t* resolver_probe_next_at;
    uint64_t* resolver_probe_delay;
    uint64_t* resolver_path_ids;
    uint64_t* resolver_rtt_us;
    uint64_t* resolver_sent;
    uint64_t* resolver_lost;
    uint64_t* resolver_last_sent;
    uint64_t* resolver_last_lost;
    uint64_t* resolver_loss_permille;
    uint64_t* resolver_cwin;
    uint64_t* resolver_sampled_at;
    uint64_t* resolver_unhealthy_until;
    uint64_t* resolver_quality_log_next_at;
    size_t* resolver_send_mtu;
    uint64_t* resolver_mtu_adjusted_at;
    uint8_t* resolver_mtu_good_windows;
    bool* resolver_rtt_ready;
    uint8_t control_match_pos;
    bool packed_queries_enabled;
    bool resolver_paths_unavailable_logged;
    bool resolver_selection_in_progress;
    bool resolver_selection_done;
    bool resolver_switch_pending;
    bool resolver_failover_pending;
    uint8_t active_resolver_bad_windows;
    uint64_t resolver_health_next_at;
    uint64_t resolver_reselection_next_at;
    uint64_t resolver_failover_next_at;
    uint64_t resolver_selection_started_at;
    uint64_t resolver_selection_deadline_at;
} slipstream_client_ctx_t;

char* client_domain_name = NULL;
size_t client_domain_name_len = 0;
static size_t client_legacy_query_payload_budget = 0;
static size_t client_packed_query_payload_budget = 0;
static size_t client_query_payload_budget = 0;
static size_t client_query_label_max = SLIPSTREAM_DNS_LEGACY_ENCODED_LABEL_MAX;
static bool client_packed_queries_allowed = false;
static const uint32_t client_response_mtu_max = SLIPSTREAM_CLIENT_RESPONSE_MTU_MAX;

#define SLIPSTREAM_DNS_NAME_BUFSIZE 255

static size_t slipstream_base32_encoded_len(size_t raw_len) {
    return (raw_len * 8 + 4) / 5;
}

static size_t slipstream_dotified_encoded_len(size_t encoded_len, size_t label_max) {
    if (encoded_len == 0) {
        return 0;
    }
    return encoded_len + (encoded_len - 1) / label_max;
}

static size_t slipstream_client_legacy_query_budget(size_t domain_len) {
    if (domain_len >= 240) {
        return 0;
    }
    return ((240 - domain_len) * 5) / 8;
}

static size_t slipstream_client_packed_query_budget(size_t domain_len) {
    const size_t suffix_len = domain_len + 2; /* dot before domain plus final root dot */
    if (suffix_len >= SLIPSTREAM_DNS_NAME_BUFSIZE) {
        return 0;
    }

    const size_t max_dotified_len = (SLIPSTREAM_DNS_NAME_BUFSIZE - 1) - suffix_len;
    size_t payload = (max_dotified_len * 5) / 8;
    while (payload > 0) {
        const size_t encoded_len = slipstream_base32_encoded_len(payload);
        if (slipstream_dotified_encoded_len(encoded_len, SLIPSTREAM_DNS_ENCODED_LABEL_MAX) <= max_dotified_len) {
            return payload;
        }
        payload--;
    }

    return 0;
}

static int slipstream_connect(struct sockaddr_storage* server_address,
                              picoquic_quic_t* quic, picoquic_cnx_t** cnx,
                              slipstream_client_ctx_t* client_ctx);
static void slipstream_client_apply_resolver_mtu(slipstream_client_ctx_t* client_ctx,
                                                 size_t resolver_index,
                                                 uint64_t unique_path_id,
                                                 const char* reason);
static void slipstream_client_apply_resolver_path_priorities(slipstream_client_ctx_t* client_ctx,
                                                             size_t preferred_resolver_index);
static size_t slipstream_client_clamp_adaptive_mtu(size_t mtu);
static size_t slipstream_client_find_resolver_by_path_id(slipstream_client_ctx_t* client_ctx,
                                                         picoquic_cnx_t* cnx,
                                                         uint64_t unique_path_id);

static size_t slipstream_client_next_resolver_index(const slipstream_client_ctx_t* client_ctx, size_t resolver_index) {
    if (client_ctx->server_address_count == 0) {
        return 0;
    }
    resolver_index++;
    if (resolver_index >= client_ctx->server_address_count) {
        resolver_index = 0;
    }
    return resolver_index;
}

static void slipstream_client_advertise_response_mtu(picoquic_quic_t* quic) {
    picoquic_tp_t tp = *picoquic_get_default_tp(quic);
    tp.max_packet_size = client_response_mtu_max;
    (void)picoquic_set_default_tp(quic, &tp);
}

static void slipstream_client_set_query_mtu(picoquic_quic_t* quic, size_t query_mtu) {
    picoquic_set_mtu_max(quic, (uint32_t)query_mtu);
    picoquic_set_initial_send_mtu(quic, (uint32_t)query_mtu, (uint32_t)query_mtu);
    slipstream_client_advertise_response_mtu(quic);
}

static void slipstream_client_use_legacy_queries(slipstream_client_ctx_t* client_ctx) {
    client_ctx->packed_queries_enabled = false;
    client_ctx->control_match_pos = 0;
    client_query_payload_budget = client_legacy_query_payload_budget;
    client_query_label_max = SLIPSTREAM_DNS_LEGACY_ENCODED_LABEL_MAX;
}

static void slipstream_client_enable_packed_queries(picoquic_cnx_t* cnx, slipstream_client_ctx_t* client_ctx) {
    if (!client_packed_queries_allowed) {
        fprintf(stderr, "Client packed DNS queries offered by server but disabled\n");
        return;
    }
    if (client_ctx->packed_queries_enabled || client_packed_query_payload_budget <= client_legacy_query_payload_budget) {
        return;
    }

    size_t old_query_payload_budget = client_query_payload_budget;
    client_ctx->packed_queries_enabled = true;
    client_query_payload_budget = client_packed_query_payload_budget;
    client_query_label_max = SLIPSTREAM_DNS_ENCODED_LABEL_MAX;

    picoquic_quic_t* quic = picoquic_get_quic_ctx(cnx);
    slipstream_client_set_query_mtu(quic, client_packed_query_payload_budget);

    if (client_ctx->resolver_send_mtu != NULL) {
        for (size_t i = 0; i < client_ctx->server_address_count; i++) {
            if (client_ctx->resolver_send_mtu[i] == 0 ||
                client_ctx->resolver_send_mtu[i] >= old_query_payload_budget) {
                client_ctx->resolver_send_mtu[i] = client_query_payload_budget;
            } else {
                client_ctx->resolver_send_mtu[i] =
                    slipstream_client_clamp_adaptive_mtu(client_ctx->resolver_send_mtu[i]);
            }
        }
    }

    for (int i = 0; i < cnx->nb_paths; i++) {
        if (cnx->path[i] != NULL) {
            size_t resolver_index = slipstream_client_find_resolver_by_path_id(client_ctx, cnx,
                                                                               cnx->path[i]->unique_path_id);
            if (resolver_index != SIZE_MAX) {
                slipstream_client_apply_resolver_mtu(client_ctx, resolver_index,
                                                     cnx->path[i]->unique_path_id, "applied");
            } else if (cnx->path[i]->send_mtu < client_packed_query_payload_budget) {
                cnx->path[i]->send_mtu = client_packed_query_payload_budget;
                cnx->path[i]->send_mtu_max_tried = client_packed_query_payload_budget;
                cnx->path[i]->mtu_probe_sent = 0;
            }
        }
    }

    fprintf(stderr, "Client packed DNS queries enabled: payload=%zu label=%zu\n",
            client_query_payload_budget, client_query_label_max);
}

static void slipstream_client_process_control_stream(picoquic_cnx_t* cnx,
                                                     slipstream_client_ctx_t* client_ctx,
                                                     const uint8_t* bytes,
                                                     size_t length) {
    const char* magic = SLIPSTREAM_QUERY_PACK_CONTROL;
    const size_t magic_len = sizeof(SLIPSTREAM_QUERY_PACK_CONTROL) - 1;

    for (size_t i = 0; i < length; i++) {
        if (bytes[i] == (uint8_t)magic[client_ctx->control_match_pos]) {
            client_ctx->control_match_pos++;
            if (client_ctx->control_match_pos == magic_len) {
                client_ctx->control_match_pos = 0;
                slipstream_client_enable_packed_queries(cnx, client_ctx);
                return;
            }
        } else {
            client_ctx->control_match_pos = bytes[i] == (uint8_t)magic[0] ? 1 : 0;
        }
    }
}

ssize_t client_encode_segment(dns_packet_t* packet, size_t* packet_len, const unsigned char* src_buf, size_t src_buf_len) {
    char name[SLIPSTREAM_DNS_NAME_BUFSIZE];
    if (src_buf_len > client_query_payload_budget) {
        DBG_PRINTF("query payload too large: %zu > %zu", src_buf_len, client_query_payload_budget);
        return -1;
    }

    const size_t len = b32_encode(&name[0], (const char*) src_buf, src_buf_len, true, false);
    const size_t encoded_len = slipstream_inline_dotify_label_max(name, sizeof(name), len, client_query_label_max);
    if (encoded_len == (size_t)-1) {
        DBG_PRINTF("could not dotify query payload: encoded_len=%zu", len);
        return -1;
    }
    name[encoded_len] = '.';

    memcpy(&name[encoded_len + 1], client_domain_name, client_domain_name_len);
    name[encoded_len + 1 + client_domain_name_len] = '.';
    name[encoded_len + 1 + client_domain_name_len + 1] = '\0';

    dns_question_t question;
    question.name = name;
    question.type = RR_TXT;
    question.class = CLASS_IN;

    dns_answer_t edns = {0};
    edns.opt.name = ".";
    edns.opt.type = RR_OPT;
    edns.opt.class = CLASS_UNKNOWN;
    edns.opt.ttl = 0;
    edns.opt.udp_payload = 1232;

    dns_query_t query = {0};
    query.id = rand() % UINT16_MAX;
    query.query = true;
    query.opcode = OP_QUERY;
    query.rd = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &question;
    query.arcount = 1;
    query.additional = &edns;

    const dns_rcode_t rc = dns_encode(packet, packet_len, &query);
    if (rc != RCODE_OKAY) {
        DBG_PRINTF( "dns_encode() = (%d) %s: %s\n", rc, dns_rcode_text(rc), name);
        return -1;
    }

    return 0;
}

ssize_t client_encode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, size_t* segment_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr) {
    *dest_buf = NULL;

    // optimize path for single segment
    if (src_buf_len <= *segment_len) {
#ifdef NOENCODE
        *dest_buf = malloc(src_buf_len);
        memcpy((void*)*dest_buf, src_buf, src_buf_len);

        return src_buf_len;
#endif
        size_t packet_len = MAX_DNS_QUERY_SIZE;
        unsigned char* packet = malloc(packet_len);
        if (packet == NULL) {
            return -1;
        }
        const ssize_t ret = client_encode_segment((dns_packet_t*) packet, &packet_len, src_buf, src_buf_len);
        if (ret < 0) {
            free(packet);
            return -1;
        }

        *dest_buf = packet;
        *segment_len = packet_len;

        return packet_len;
    }

#ifdef NOENCODE
    assert(false);
#endif

    size_t num_segments = (src_buf_len + *segment_len - 1) / *segment_len;
    unsigned char* packets = malloc(MAX_DNS_QUERY_SIZE * num_segments);
    if (packets == NULL) {
        return -1;
    }
    unsigned char* current_packet = packets;

    const unsigned char* segment = src_buf;
    size_t first_packet_len = 0;
    for (size_t i = 0; i < num_segments; i++) {
        size_t current_segment_len = MIN(*segment_len, src_buf_len - (size_t)(segment - src_buf));
        size_t packet_len = MAX_DNS_QUERY_SIZE;
        const ssize_t ret = client_encode_segment((dns_packet_t*) current_packet, &packet_len, segment, current_segment_len);
        if (ret < 0) {
            free(packets);
            return -1;
        }

        if (first_packet_len == 0) {
            first_packet_len = packet_len;
        } else {
            if (packet_len > first_packet_len) {
                DBG_PRINTF("current encoded segment length %d > %d than first segment\n", packet_len, first_packet_len);
                free(packets);
                return -1;
            }
        }

        current_packet += packet_len;
        segment += current_segment_len;
    }

    *dest_buf = packets;
    *segment_len = first_packet_len;

    return current_packet - packets;
}

ssize_t client_decode(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage* peer_addr, struct sockaddr_storage* local_addr) {
    *dest_buf = NULL;

#ifdef NODECODE
    *dest_buf = malloc(src_buf_len);
    memcpy((void*)*dest_buf, src_buf, src_buf_len);

    return src_buf_len;
#endif

    size_t bufsize = DNS_DECODEBUF_4K * sizeof(dns_decoded_t);
    dns_decoded_t decoded[DNS_DECODEBUF_4K] = {0};
    const dns_rcode_t rc = dns_decode(decoded, &bufsize, (const dns_packet_t*) src_buf, src_buf_len);
    if (rc != RCODE_OKAY) {
        DBG_PRINTF("dns_decode() = (%d) %s", rc, dns_rcode_text(rc));
        return 0;
    }

    const dns_query_t *query = (dns_query_t *)decoded;

    if (query->query == 1) {
        DBG_PRINTF("[%d] dns record is not a response", query->id, NULL);
        return 0;
    }

    if (query->rcode == RCODE_NAME_ERROR) {
        // returned when the server has nothing to send
        return 0;
    }

    if (query->rcode != RCODE_OKAY) {
        DBG_PRINTF("[%d] dns record rcode not okay: %d", query->id, query->rcode);
        return 0;
    }

    if (query->ancount != 1) {
        // DBG_PRINTF("[%d] dns record should contain exactly one answer", query->id);
        return 0;
    }

    dns_txt_t *answer_txt = (dns_txt_t*) &query->answers[0];
    if (answer_txt->type != RR_TXT) {
        DBG_PRINTF("[%d] answer type is not TXT", query->id, NULL);
        return 0;
    }

    *dest_buf = malloc(answer_txt->len);
    memcpy((void*)*dest_buf, answer_txt->text, answer_txt->len);

    return answer_txt->len;
}

slipstream_client_stream_ctx_t* slipstream_client_create_stream_ctx(slipstream_client_ctx_t* client_ctx,
                                                                    int sock_fd) {
    slipstream_client_stream_ctx_t* stream_ctx = malloc(sizeof(slipstream_client_stream_ctx_t));

    if (stream_ctx == NULL) {
        fprintf(stderr, "Memory Error, cannot create stream for sock %d\n", sock_fd);
        return NULL;
    }

    memset(stream_ctx, 0, sizeof(slipstream_client_stream_ctx_t));
    if (client_ctx->first_stream == NULL) {
        client_ctx->first_stream = stream_ctx;
    } else {
        stream_ctx->next_stream = client_ctx->first_stream;
        stream_ctx->next_stream->previous_stream = stream_ctx;
        client_ctx->first_stream = stream_ctx;
    }
    stream_ctx->fd = sock_fd;
    stream_ctx->stream_id = -1;
    stream_ctx->ref_count = 1;

    return stream_ctx;
}

static void slipstream_client_stream_retain(slipstream_client_stream_ctx_t* stream_ctx) {
    __sync_add_and_fetch(&stream_ctx->ref_count, 1);
}

static void slipstream_client_stream_release(slipstream_client_stream_ctx_t* stream_ctx) {
    if (__sync_sub_and_fetch(&stream_ctx->ref_count, 1) == 0) {
        if (stream_ctx->fd != -1) {
            close(stream_ctx->fd);
            stream_ctx->fd = -1;
        }
        free(stream_ctx);
    }
}

static void slipstream_client_free_stream_ctx(slipstream_client_ctx_t* client_ctx, slipstream_client_stream_ctx_t* stream_ctx) {
    if (stream_ctx->previous_stream != NULL) {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }
    if (stream_ctx->next_stream != NULL) {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }
    if (client_ctx->first_stream == stream_ctx) {
        client_ctx->first_stream = stream_ctx->next_stream;
    }

    if (client_ctx->cnx != NULL && stream_ctx->stream_id != UINT64_MAX) {
        picoquic_unlink_app_stream_ctx(client_ctx->cnx, stream_ctx->stream_id);
        stream_ctx->stream_id = UINT64_MAX;
    }

    if (stream_ctx->fd != -1) {
        close(stream_ctx->fd);
        stream_ctx->fd = -1;
    }

    slipstream_client_stream_release(stream_ctx);
}

static void slipstream_client_free_context(slipstream_client_ctx_t* client_ctx) {
    slipstream_client_stream_ctx_t* stream_ctx;

    /* Delete any remaining stream context */
    while ((stream_ctx = client_ctx->first_stream) != NULL) {
        slipstream_client_free_stream_ctx(client_ctx, stream_ctx);
    }

    client_ctx->closed = true;
}

static void slipstream_client_reset_paths(slipstream_client_ctx_t* client_ctx) {
    client_ctx->resolver_paths_unavailable_logged = false;
    client_ctx->resolver_selection_in_progress = false;
    client_ctx->resolver_selection_done = false;
    client_ctx->resolver_switch_pending = false;
    client_ctx->resolver_failover_pending = false;
    client_ctx->active_resolver_bad_windows = 0;
    client_ctx->resolver_health_next_at = 0;
    client_ctx->resolver_reselection_next_at = 0;
    client_ctx->resolver_selection_started_at = 0;
    client_ctx->resolver_selection_deadline_at = 0;
    for (size_t i = 0; i < client_ctx->server_address_count; i++) {
        client_ctx->server_addresses[i].added = false;
        if (client_ctx->resolver_probe_next_at != NULL) {
            client_ctx->resolver_probe_next_at[i] = 0;
        }
        if (client_ctx->resolver_probe_delay != NULL) {
            client_ctx->resolver_probe_delay[i] = 0;
        }
        if (client_ctx->resolver_path_ids != NULL) {
            client_ctx->resolver_path_ids[i] = SLIPSTREAM_RESOLVER_PATH_ID_UNKNOWN;
        }
        if (client_ctx->resolver_rtt_us != NULL) {
            client_ctx->resolver_rtt_us[i] = 0;
        }
        if (client_ctx->resolver_sent != NULL) {
            client_ctx->resolver_sent[i] = 0;
        }
        if (client_ctx->resolver_lost != NULL) {
            client_ctx->resolver_lost[i] = 0;
        }
        if (client_ctx->resolver_last_sent != NULL) {
            client_ctx->resolver_last_sent[i] = 0;
        }
        if (client_ctx->resolver_last_lost != NULL) {
            client_ctx->resolver_last_lost[i] = 0;
        }
        if (client_ctx->resolver_loss_permille != NULL) {
            client_ctx->resolver_loss_permille[i] = 0;
        }
        if (client_ctx->resolver_cwin != NULL) {
            client_ctx->resolver_cwin[i] = 0;
        }
        if (client_ctx->resolver_sampled_at != NULL) {
            client_ctx->resolver_sampled_at[i] = 0;
        }
        if (client_ctx->resolver_quality_log_next_at != NULL) {
            client_ctx->resolver_quality_log_next_at[i] = 0;
        }
        if (client_ctx->resolver_send_mtu != NULL) {
            if (client_ctx->resolver_send_mtu[i] == 0) {
                client_ctx->resolver_send_mtu[i] = client_query_payload_budget;
            } else {
                client_ctx->resolver_send_mtu[i] =
                    slipstream_client_clamp_adaptive_mtu(client_ctx->resolver_send_mtu[i]);
            }
        }
        if (client_ctx->resolver_mtu_good_windows != NULL) {
            client_ctx->resolver_mtu_good_windows[i] = 0;
        }
        if (client_ctx->resolver_rtt_ready != NULL) {
            client_ctx->resolver_rtt_ready[i] = false;
        }
    }
}

static void slipstream_client_schedule_reconnect(slipstream_client_ctx_t* client_ctx, uint64_t current_time) {
    if (client_ctx->reconnect_delay == 0) {
        client_ctx->reconnect_delay = 1000000;
    }
    const uint64_t delay = client_ctx->reconnect_delay;
    client_ctx->reconnect_pending = true;
    client_ctx->reconnect_at = current_time + delay;
    fprintf(stderr, "Client reconnect scheduled in %.1f seconds\n", (double)delay / 1000000.0);
    if (client_ctx->reconnect_delay < 30000000) {
        client_ctx->reconnect_delay *= 2;
        if (client_ctx->reconnect_delay > 30000000) {
            client_ctx->reconnect_delay = 30000000;
        }
    }
}

static void slipstream_client_schedule_active_poll(slipstream_client_ctx_t* client_ctx, uint64_t current_time) {
    if (!client_ctx->ready || client_ctx->cnx == NULL || client_ctx->first_stream == NULL) {
        if (client_ctx->cnx != NULL) {
            picoquic_set_app_wake_time(client_ctx->cnx, 0);
        }
        return;
    }

    const uint64_t next_poll = current_time + SLIPSTREAM_ACTIVE_POLL_INTERVAL_US;
    if (client_ctx->cnx->app_wake_time == 0 || client_ctx->cnx->app_wake_time > next_poll) {
        picoquic_set_app_wake_time(client_ctx->cnx, next_poll);
    }
}

static void slipstream_client_record_resolver_path_id(slipstream_client_ctx_t* client_ctx,
                                                      size_t resolver_index,
                                                      uint64_t unique_path_id) {
    if (client_ctx->resolver_path_ids == NULL || resolver_index >= client_ctx->server_address_count) {
        return;
    }

    if (client_ctx->resolver_path_ids[resolver_index] != unique_path_id) {
        client_ctx->resolver_path_ids[resolver_index] = unique_path_id;
        if (client_ctx->resolver_rtt_us != NULL) {
            client_ctx->resolver_rtt_us[resolver_index] = 0;
        }
        if (client_ctx->resolver_sent != NULL) {
            client_ctx->resolver_sent[resolver_index] = 0;
        }
        if (client_ctx->resolver_lost != NULL) {
            client_ctx->resolver_lost[resolver_index] = 0;
        }
        if (client_ctx->resolver_last_sent != NULL) {
            client_ctx->resolver_last_sent[resolver_index] = 0;
        }
        if (client_ctx->resolver_last_lost != NULL) {
            client_ctx->resolver_last_lost[resolver_index] = 0;
        }
        if (client_ctx->resolver_loss_permille != NULL) {
            client_ctx->resolver_loss_permille[resolver_index] = 0;
        }
        if (client_ctx->resolver_cwin != NULL) {
            client_ctx->resolver_cwin[resolver_index] = 0;
        }
        if (client_ctx->resolver_sampled_at != NULL) {
            client_ctx->resolver_sampled_at[resolver_index] = 0;
        }
        if (client_ctx->resolver_mtu_good_windows != NULL) {
            client_ctx->resolver_mtu_good_windows[resolver_index] = 0;
        }
        if (client_ctx->resolver_rtt_ready != NULL) {
            client_ctx->resolver_rtt_ready[resolver_index] = false;
        }
    }
}

static size_t slipstream_client_find_resolver_by_path_id(slipstream_client_ctx_t* client_ctx,
                                                         picoquic_cnx_t* cnx,
                                                         uint64_t unique_path_id) {
    if (client_ctx->resolver_path_ids != NULL) {
        for (size_t i = 0; i < client_ctx->server_address_count; i++) {
            if (client_ctx->resolver_path_ids[i] == unique_path_id) {
                return i;
            }
        }
    }

    if (cnx != NULL) {
        struct sockaddr_storage peer_addr = {0};
        if (picoquic_get_path_addr(cnx, unique_path_id, 2, &peer_addr) == 0) {
            for (size_t i = 0; i < client_ctx->server_address_count; i++) {
                if (picoquic_compare_addr((const struct sockaddr*)&client_ctx->server_addresses[i].server_address,
                                          (const struct sockaddr*)&peer_addr) == 0) {
                    return i;
                }
            }
        }
    }

    return SIZE_MAX;
}

static uint64_t slipstream_client_latency_from_quality(const picoquic_path_quality_t* quality) {
    if (quality->rtt_sample != 0) {
        return quality->rtt_sample;
    }
    if (quality->rtt != 0) {
        return quality->rtt;
    }
    if (quality->rtt_min != 0) {
        return quality->rtt_min;
    }
    return 0;
}

static uint32_t slipstream_client_loss_permille(uint64_t lost_delta, uint64_t sent_delta) {
    if (sent_delta == 0) {
        return 0;
    }
    uint64_t permille = (lost_delta * 1000) / sent_delta;
    return permille > 1000 ? 1000 : (uint32_t)permille;
}

static bool slipstream_client_resolver_in_cooldown(const slipstream_client_ctx_t* client_ctx,
                                                   size_t resolver_index,
                                                   uint64_t current_time) {
    return client_ctx->resolver_unhealthy_until != NULL &&
        resolver_index < client_ctx->server_address_count &&
        current_time < client_ctx->resolver_unhealthy_until[resolver_index];
}

static uint64_t slipstream_client_resolver_score(const slipstream_client_ctx_t* client_ctx,
                                                 size_t resolver_index,
                                                 uint64_t current_time,
                                                 bool ignore_cooldown) {
    if (client_ctx->resolver_rtt_ready == NULL || client_ctx->resolver_rtt_us == NULL ||
        resolver_index >= client_ctx->server_address_count ||
        !client_ctx->resolver_rtt_ready[resolver_index]) {
        return UINT64_MAX;
    }
    if (client_ctx->resolver_sampled_at != NULL &&
        (client_ctx->resolver_sampled_at[resolver_index] == 0 ||
         current_time - client_ctx->resolver_sampled_at[resolver_index] > SLIPSTREAM_RESOLVER_SAMPLE_STALE_US)) {
        return UINT64_MAX;
    }

    uint64_t score = client_ctx->resolver_rtt_us[resolver_index];
    if (!ignore_cooldown &&
        slipstream_client_resolver_in_cooldown(client_ctx, resolver_index, current_time)) {
        score += SLIPSTREAM_RESOLVER_UNHEALTHY_COOLDOWN_US;
    }
    if (client_ctx->resolver_loss_permille != NULL) {
        score += client_ctx->resolver_loss_permille[resolver_index] *
            SLIPSTREAM_RESOLVER_LOSS_SCORE_US_PER_PERMILLE;
    }
    if (client_ctx->resolver_cwin != NULL &&
        client_ctx->resolver_cwin[resolver_index] > 0 &&
        client_ctx->resolver_cwin[resolver_index] <= SLIPSTREAM_RESOLVER_CWIN_COLLAPSED_BYTES) {
        score += SLIPSTREAM_RESOLVER_CWIN_COLLAPSE_PENALTY_US;
    }

    return score;
}

static size_t slipstream_client_adaptive_mtu_floor(void) {
    size_t floor = SLIPSTREAM_RESOLVER_MTU_MIN_BYTES;
    if (client_query_payload_budget < floor) {
        floor = client_query_payload_budget;
    }
    if (floor < PICOQUIC_MIN_SEGMENT_SIZE && client_query_payload_budget >= PICOQUIC_MIN_SEGMENT_SIZE) {
        floor = PICOQUIC_MIN_SEGMENT_SIZE;
    }
    return floor;
}

static size_t slipstream_client_clamp_adaptive_mtu(size_t mtu) {
    size_t floor = slipstream_client_adaptive_mtu_floor();
    if (mtu < floor) {
        mtu = floor;
    }
    if (mtu > client_query_payload_budget) {
        mtu = client_query_payload_budget;
    }
    return mtu;
}

static size_t slipstream_client_connect_mtu_floor(void) {
    size_t floor = slipstream_client_adaptive_mtu_floor();
    if (floor < PICOQUIC_ENFORCED_INITIAL_MTU &&
        client_query_payload_budget >= PICOQUIC_ENFORCED_INITIAL_MTU) {
        floor = PICOQUIC_ENFORCED_INITIAL_MTU;
    }
    return floor;
}

static size_t slipstream_client_clamp_connect_mtu(size_t mtu) {
    size_t floor = slipstream_client_connect_mtu_floor();
    if (mtu < floor) {
        mtu = floor;
    }
    if (mtu > client_query_payload_budget) {
        mtu = client_query_payload_budget;
    }
    return mtu;
}

static void slipstream_client_set_path_mtu(picoquic_path_t* path, size_t target_mtu) {
    path->send_mtu = target_mtu;
    path->send_mtu_max_tried = target_mtu;
    path->mtu_probe_sent = 0;
}

static void slipstream_client_apply_resolver_mtu(slipstream_client_ctx_t* client_ctx,
                                                 size_t resolver_index,
                                                 uint64_t unique_path_id,
                                                 const char* reason) {
    if (client_ctx->cnx == NULL || client_ctx->resolver_send_mtu == NULL ||
        resolver_index >= client_ctx->server_address_count ||
        unique_path_id == SLIPSTREAM_RESOLVER_PATH_ID_UNKNOWN) {
        return;
    }

    int path_index = picoquic_get_path_id_from_unique(client_ctx->cnx, unique_path_id);
    if (path_index < 0 || path_index >= client_ctx->cnx->nb_paths ||
        client_ctx->cnx->path[path_index] == NULL) {
        return;
    }

    picoquic_path_t* path = client_ctx->cnx->path[path_index];
    size_t target_mtu = slipstream_client_clamp_adaptive_mtu(client_ctx->resolver_send_mtu[resolver_index]);
    if (target_mtu == 0 || path->send_mtu == target_mtu) {
        return;
    }

    char resolver_text[NI_MAXHOST + NI_MAXSERV + 8];
    size_t old_mtu = path->send_mtu;
    slipstream_client_set_path_mtu(path, target_mtu);
    uint64_t loss_permille = client_ctx->resolver_loss_permille == NULL ? 0 :
        client_ctx->resolver_loss_permille[resolver_index];
    uint64_t cwin = client_ctx->resolver_cwin == NULL ? 0 :
        client_ctx->resolver_cwin[resolver_index];
    fprintf(stderr,
            "Client resolver MTU %s: index=%zu/%zu resolver=%s path=%llu old=%zu new=%zu loss=%.1f%% cwin=%llu\n",
            reason,
            resolver_index + 1, client_ctx->server_address_count,
            slipstream_format_sockaddr(&client_ctx->server_addresses[resolver_index].server_address,
                                       resolver_text, sizeof(resolver_text)),
            (unsigned long long)unique_path_id,
            old_mtu, target_mtu,
            (double)loss_permille / 10.0,
            (unsigned long long)cwin);
}

static void slipstream_client_apply_resolver_connect_mtu(slipstream_client_ctx_t* client_ctx,
                                                         size_t resolver_index) {
    if (client_ctx->cnx == NULL || client_ctx->resolver_send_mtu == NULL ||
        resolver_index >= client_ctx->server_address_count ||
        client_ctx->cnx->path[0] == NULL) {
        return;
    }

    picoquic_path_t* path = client_ctx->cnx->path[0];
    size_t target_mtu = slipstream_client_clamp_connect_mtu(client_ctx->resolver_send_mtu[resolver_index]);
    if (target_mtu == 0 || path->send_mtu == target_mtu) {
        return;
    }

    char resolver_text[NI_MAXHOST + NI_MAXSERV + 8];
    size_t old_mtu = path->send_mtu;
    slipstream_client_set_path_mtu(path, target_mtu);
    fprintf(stderr,
            "Client resolver connect MTU applied: index=%zu/%zu resolver=%s old=%zu new=%zu\n",
            resolver_index + 1, client_ctx->server_address_count,
            slipstream_format_sockaddr(&client_ctx->server_addresses[resolver_index].server_address,
                                       resolver_text, sizeof(resolver_text)),
            old_mtu, target_mtu);
}

static void slipstream_client_note_resolver_connect_timeout(slipstream_client_ctx_t* client_ctx,
                                                            size_t resolver_index,
                                                            uint64_t current_time) {
    if (client_ctx->resolver_send_mtu == NULL ||
        resolver_index >= client_ctx->server_address_count) {
        return;
    }

    size_t current_mtu = client_ctx->resolver_send_mtu[resolver_index];
    if (current_mtu == 0) {
        current_mtu = client_query_payload_budget;
    }
    current_mtu = slipstream_client_clamp_connect_mtu(current_mtu);

    size_t floor = slipstream_client_connect_mtu_floor();
    if (current_mtu <= floor) {
        return;
    }

    size_t step = current_mtu / 4;
    if (step < SLIPSTREAM_RESOLVER_MTU_STEP_MIN_BYTES) {
        step = SLIPSTREAM_RESOLVER_MTU_STEP_MIN_BYTES;
    }
    size_t next_mtu = current_mtu > step ? current_mtu - step : floor;
    if (next_mtu < floor) {
        next_mtu = floor;
    }

    client_ctx->resolver_send_mtu[resolver_index] = next_mtu;
    if (client_ctx->resolver_mtu_adjusted_at != NULL) {
        client_ctx->resolver_mtu_adjusted_at[resolver_index] = current_time;
    }

    char resolver_text[NI_MAXHOST + NI_MAXSERV + 8];
    fprintf(stderr,
            "Client resolver connect MTU reduced after timeout: index=%zu/%zu resolver=%s old=%zu new=%zu\n",
            resolver_index + 1, client_ctx->server_address_count,
            slipstream_format_sockaddr(&client_ctx->server_addresses[resolver_index].server_address,
                                       resolver_text, sizeof(resolver_text)),
            current_mtu, next_mtu);
}

static void slipstream_client_maybe_adapt_resolver_mtu(slipstream_client_ctx_t* client_ctx,
                                                       size_t resolver_index,
                                                       uint64_t unique_path_id,
                                                       uint64_t current_time) {
    if (client_ctx->resolver_send_mtu == NULL || client_ctx->resolver_mtu_adjusted_at == NULL ||
        client_ctx->resolver_mtu_good_windows == NULL ||
        client_ctx->resolver_loss_permille == NULL ||
        resolver_index >= client_ctx->server_address_count) {
        return;
    }

    size_t current_mtu = client_ctx->resolver_send_mtu[resolver_index];
    if (current_mtu == 0) {
        current_mtu = client_query_payload_budget;
    }
    current_mtu = slipstream_client_clamp_adaptive_mtu(current_mtu);
    client_ctx->resolver_send_mtu[resolver_index] = current_mtu;

    uint64_t last_adjusted = client_ctx->resolver_mtu_adjusted_at[resolver_index];
    if (last_adjusted != 0 &&
        current_time - last_adjusted < SLIPSTREAM_RESOLVER_MTU_ADJUST_INTERVAL_US) {
        return;
    }

    uint64_t loss_permille = client_ctx->resolver_loss_permille[resolver_index];
    bool cwin_collapsed = client_ctx->resolver_cwin != NULL &&
        client_ctx->resolver_cwin[resolver_index] > 0 &&
        client_ctx->resolver_cwin[resolver_index] <= SLIPSTREAM_RESOLVER_CWIN_COLLAPSED_BYTES;
    bool bad_window = loss_permille >= SLIPSTREAM_RESOLVER_MTU_BAD_LOSS_PERMILLE ||
        (cwin_collapsed && loss_permille > 0);

    if (bad_window) {
        size_t floor = slipstream_client_adaptive_mtu_floor();
        if (current_mtu > floor) {
            size_t step = current_mtu / 4;
            if (step < SLIPSTREAM_RESOLVER_MTU_STEP_MIN_BYTES) {
                step = SLIPSTREAM_RESOLVER_MTU_STEP_MIN_BYTES;
            }
            size_t next_mtu = current_mtu > step ? current_mtu - step : floor;
            if (next_mtu < floor) {
                next_mtu = floor;
            }
            client_ctx->resolver_send_mtu[resolver_index] = next_mtu;
            client_ctx->resolver_mtu_adjusted_at[resolver_index] = current_time;
            client_ctx->resolver_mtu_good_windows[resolver_index] = 0;
            if (client_ctx->resolver_unhealthy_until != NULL &&
                loss_permille >= SLIPSTREAM_RESOLVER_BAD_LOSS_PERMILLE) {
                client_ctx->resolver_unhealthy_until[resolver_index] =
                    current_time + SLIPSTREAM_RESOLVER_UNHEALTHY_COOLDOWN_US;
            }
            slipstream_client_apply_resolver_mtu(client_ctx, resolver_index, unique_path_id, "reduced");
        }
        return;
    }

    if (loss_permille <= SLIPSTREAM_RESOLVER_MTU_RECOVERY_LOSS_PERMILLE && !cwin_collapsed) {
        if (client_ctx->resolver_mtu_good_windows[resolver_index] < UINT8_MAX) {
            client_ctx->resolver_mtu_good_windows[resolver_index]++;
        }
        if (client_ctx->resolver_mtu_good_windows[resolver_index] >=
            SLIPSTREAM_RESOLVER_MTU_GOOD_WINDOWS_TO_GROW &&
            current_mtu < client_query_payload_budget) {
            size_t next_mtu = current_mtu + SLIPSTREAM_RESOLVER_MTU_GROW_STEP_BYTES;
            if (next_mtu > client_query_payload_budget) {
                next_mtu = client_query_payload_budget;
            }
            client_ctx->resolver_send_mtu[resolver_index] = next_mtu;
            client_ctx->resolver_mtu_adjusted_at[resolver_index] = current_time;
            client_ctx->resolver_mtu_good_windows[resolver_index] = 0;
            slipstream_client_apply_resolver_mtu(client_ctx, resolver_index, unique_path_id, "raised");
        }
    } else {
        client_ctx->resolver_mtu_good_windows[resolver_index] = 0;
    }
}

static bool slipstream_client_sample_resolver_latency(slipstream_client_ctx_t* client_ctx,
                                                      size_t resolver_index,
                                                      uint64_t unique_path_id) {
    if (client_ctx->cnx == NULL || client_ctx->resolver_rtt_us == NULL ||
        client_ctx->resolver_rtt_ready == NULL ||
        resolver_index >= client_ctx->server_address_count ||
        unique_path_id == SLIPSTREAM_RESOLVER_PATH_ID_UNKNOWN) {
        return false;
    }

    uint64_t current_time = picoquic_current_time();
    picoquic_path_quality_t quality = {0};
    if (picoquic_get_path_quality(client_ctx->cnx, unique_path_id, &quality) != 0) {
        return false;
    }

    uint64_t latency = slipstream_client_latency_from_quality(&quality);
    if (latency == 0) {
        return false;
    }

    uint64_t previous_sent = client_ctx->resolver_sent == NULL ? 0 : client_ctx->resolver_sent[resolver_index];
    uint64_t previous_lost = client_ctx->resolver_lost == NULL ? 0 : client_ctx->resolver_lost[resolver_index];
    bool first_sample = !client_ctx->resolver_rtt_ready[resolver_index];
    bool active_resolver = resolver_index == client_ctx->active_resolver_index;
    bool fresh_observation = first_sample || active_resolver ||
        quality.sent != previous_sent || quality.lost != previous_lost;

    bool sample_ready = client_ctx->resolver_rtt_ready[resolver_index];
    if (fresh_observation) {
        if (first_sample || client_ctx->resolver_rtt_us[resolver_index] == 0) {
            client_ctx->resolver_rtt_us[resolver_index] = latency;
        } else {
            client_ctx->resolver_rtt_us[resolver_index] =
                (client_ctx->resolver_rtt_us[resolver_index] * 3 + latency) / 4;
        }
        if (client_ctx->resolver_sampled_at != NULL) {
            client_ctx->resolver_sampled_at[resolver_index] = current_time;
        }
        sample_ready = true;
    } else if (client_ctx->resolver_sampled_at != NULL &&
        client_ctx->resolver_sampled_at[resolver_index] != 0 &&
        current_time - client_ctx->resolver_sampled_at[resolver_index] > SLIPSTREAM_RESOLVER_SAMPLE_STALE_US) {
        sample_ready = false;
    }

    client_ctx->resolver_rtt_ready[resolver_index] = sample_ready;

    if (client_ctx->resolver_sent != NULL) {
        client_ctx->resolver_sent[resolver_index] = quality.sent;
    }
    if (client_ctx->resolver_lost != NULL) {
        client_ctx->resolver_lost[resolver_index] = quality.lost;
    }
    if (client_ctx->resolver_cwin != NULL) {
        client_ctx->resolver_cwin[resolver_index] = quality.cwin;
    }

    bool loss_window_updated = false;
    if (client_ctx->resolver_last_sent != NULL && client_ctx->resolver_last_lost != NULL &&
        client_ctx->resolver_loss_permille != NULL) {
        uint64_t last_sent = client_ctx->resolver_last_sent[resolver_index];
        uint64_t last_lost = client_ctx->resolver_last_lost[resolver_index];
        if (quality.sent >= last_sent && quality.lost >= last_lost) {
            uint64_t sent_delta = quality.sent - last_sent;
            uint64_t lost_delta = quality.lost - last_lost;
            if (sent_delta >= SLIPSTREAM_RESOLVER_HEALTH_MIN_SENT_DELTA) {
                client_ctx->resolver_loss_permille[resolver_index] =
                    slipstream_client_loss_permille(lost_delta, sent_delta);
                loss_window_updated = true;
            }
        }
        client_ctx->resolver_last_sent[resolver_index] = quality.sent;
        client_ctx->resolver_last_lost[resolver_index] = quality.lost;
    }

    if (loss_window_updated) {
        slipstream_client_maybe_adapt_resolver_mtu(client_ctx, resolver_index, unique_path_id, current_time);
    }

    return sample_ready;
}

static void slipstream_client_discover_resolver_paths(slipstream_client_ctx_t* client_ctx) {
    picoquic_cnx_t* cnx = client_ctx->cnx;
    if (cnx == NULL || client_ctx->resolver_path_ids == NULL) {
        return;
    }

    for (int path_index = 0; path_index < cnx->nb_paths; path_index++) {
        if (cnx->path[path_index] == NULL) {
            continue;
        }
        for (size_t i = 0; i < client_ctx->server_address_count; i++) {
            if (picoquic_compare_addr((const struct sockaddr*)&client_ctx->server_addresses[i].server_address,
                                      (const struct sockaddr*)&cnx->path[path_index]->peer_addr) == 0) {
                uint64_t unique_path_id = cnx->path[path_index]->unique_path_id;
                slipstream_client_record_resolver_path_id(client_ctx, i, unique_path_id);
                slipstream_client_apply_resolver_mtu(client_ctx, i, unique_path_id, "applied");
                (void)slipstream_client_sample_resolver_latency(client_ctx, i, unique_path_id);
                break;
            }
        }
    }
}

static void slipstream_client_forget_resolver_path(slipstream_client_ctx_t* client_ctx,
                                                   uint64_t unique_path_id) {
    if (client_ctx->resolver_path_ids == NULL) {
        return;
    }

    for (size_t i = 0; i < client_ctx->server_address_count; i++) {
        if (client_ctx->resolver_path_ids[i] == unique_path_id) {
            client_ctx->resolver_path_ids[i] = SLIPSTREAM_RESOLVER_PATH_ID_UNKNOWN;
            if (client_ctx->resolver_rtt_us != NULL) {
                client_ctx->resolver_rtt_us[i] = 0;
            }
            if (client_ctx->resolver_rtt_ready != NULL) {
                client_ctx->resolver_rtt_ready[i] = false;
            }
            if (client_ctx->resolver_sampled_at != NULL) {
                client_ctx->resolver_sampled_at[i] = 0;
            }
            client_ctx->server_addresses[i].added = false;
        }
    }
}

static bool slipstream_client_all_resolvers_sampled(const slipstream_client_ctx_t* client_ctx) {
    if (client_ctx->resolver_rtt_ready == NULL) {
        return false;
    }

    for (size_t i = 0; i < client_ctx->server_address_count; i++) {
        if (!client_ctx->resolver_rtt_ready[i]) {
            return false;
        }
    }
    return true;
}

static void slipstream_client_apply_resolver_path_priorities(slipstream_client_ctx_t* client_ctx,
                                                             size_t preferred_resolver_index) {
    picoquic_cnx_t* cnx = client_ctx->cnx;
    if (cnx == NULL || client_ctx->resolver_path_ids == NULL) {
        return;
    }

    for (size_t i = 0; i < client_ctx->server_address_count; i++) {
        uint64_t unique_path_id = client_ctx->resolver_path_ids[i];
        if (unique_path_id == SLIPSTREAM_RESOLVER_PATH_ID_UNKNOWN) {
            continue;
        }

        int path_index = picoquic_get_path_id_from_unique(cnx, unique_path_id);
        if (path_index < 0 || path_index >= cnx->nb_paths ||
            cnx->path[path_index] == NULL || cnx->path[path_index]->path_is_demoted) {
            continue;
        }

        picoquic_path_status_enum status =
            i == preferred_resolver_index ? picoquic_path_status_available : picoquic_path_status_standby;
        (void)picoquic_set_path_status(cnx, unique_path_id, status);
    }
}

static size_t slipstream_client_best_sampled_resolver(const slipstream_client_ctx_t* client_ctx,
                                                      bool* has_sample,
                                                      uint64_t current_time) {
    size_t best_index = client_ctx->active_resolver_index;
    uint64_t best_score = UINT64_MAX;
    *has_sample = false;

    if (client_ctx->resolver_rtt_ready == NULL || client_ctx->resolver_rtt_us == NULL) {
        return best_index;
    }

    for (size_t i = 0; i < client_ctx->server_address_count; i++) {
        if (!client_ctx->resolver_rtt_ready[i]) {
            continue;
        }
        uint64_t score = slipstream_client_resolver_score(client_ctx, i, current_time, false);
        if (score == UINT64_MAX) {
            continue;
        }
        if (!*has_sample || score < best_score) {
            *has_sample = true;
            best_score = score;
            best_index = i;
        }
    }

    return best_index;
}

static void slipstream_client_log_resolver_selection(slipstream_client_ctx_t* client_ctx,
                                                     size_t best_index,
                                                     bool has_sample,
                                                     uint64_t current_time) {
    char resolver_text[NI_MAXHOST + NI_MAXSERV + 8];
    for (size_t i = 0; i < client_ctx->server_address_count; i++) {
        const char* formatted = slipstream_format_sockaddr(&client_ctx->server_addresses[i].server_address,
                                                           resolver_text, sizeof(resolver_text));
        if (client_ctx->resolver_rtt_ready != NULL && client_ctx->resolver_rtt_ready[i] &&
            slipstream_client_resolver_score(client_ctx, i, current_time, true) != UINT64_MAX) {
            uint64_t loss_permille = client_ctx->resolver_loss_permille == NULL ? 0 :
                client_ctx->resolver_loss_permille[i];
            uint64_t cwin = client_ctx->resolver_cwin == NULL ? 0 :
                client_ctx->resolver_cwin[i];
            size_t send_mtu = client_ctx->resolver_send_mtu == NULL ? client_query_payload_budget :
                slipstream_client_clamp_adaptive_mtu(client_ctx->resolver_send_mtu[i]);
            fprintf(stderr,
                    "Client resolver latency: index=%zu/%zu resolver=%s rtt=%.1fms loss=%.1f%% cwin=%llu mtu=%zu%s\n",
                    i + 1, client_ctx->server_address_count, formatted,
                    (double)client_ctx->resolver_rtt_us[i] / 1000.0,
                    (double)loss_permille / 10.0,
                    (unsigned long long)cwin,
                    send_mtu,
                    i == best_index ? " best" : "");
        } else {
            fprintf(stderr, "Client resolver latency: index=%zu/%zu resolver=%s unavailable\n",
                    i + 1, client_ctx->server_address_count, formatted);
        }
    }

    if (has_sample) {
        fprintf(stderr, "Client resolver selection complete: best index=%zu/%zu\n",
                best_index + 1, client_ctx->server_address_count);
    } else {
        fprintf(stderr, "Client resolver selection complete: no resolver RTT samples; keeping active index=%zu/%zu\n",
                client_ctx->active_resolver_index + 1, client_ctx->server_address_count);
    }
}

static void slipstream_client_select_resolver(slipstream_client_ctx_t* client_ctx,
                                              size_t resolver_index,
                                              uint64_t current_time,
                                              bool force_reconnect,
                                              const char* reason) {
    if (resolver_index >= client_ctx->server_address_count ||
        resolver_index == client_ctx->active_resolver_index) {
        return;
    }

    char old_text[NI_MAXHOST + NI_MAXSERV + 8];
    char new_text[NI_MAXHOST + NI_MAXSERV + 8];
    size_t old_index = client_ctx->active_resolver_index;
    fprintf(stderr,
            "Client selected resolver (%s): old=%s index=%zu/%zu new=%s index=%zu/%zu\n",
            reason,
            old_index < client_ctx->server_address_count ?
                slipstream_format_sockaddr(&client_ctx->server_addresses[old_index].server_address,
                                           old_text, sizeof(old_text)) : "unknown",
            old_index + 1, client_ctx->server_address_count,
            slipstream_format_sockaddr(&client_ctx->server_addresses[resolver_index].server_address,
                                       new_text, sizeof(new_text)),
            resolver_index + 1, client_ctx->server_address_count);

    client_ctx->next_resolver_index = resolver_index;
    if (client_ctx->first_stream == NULL || force_reconnect) {
        client_ctx->resolver_switch_pending = true;
        client_ctx->resolver_failover_pending = force_reconnect;
        client_ctx->reconnect_pending = true;
        client_ctx->reconnect_at = current_time;
        fprintf(stderr,
                "Client scheduled immediate reconnect to make resolver index=%zu/%zu the main resolver%s\n",
                resolver_index + 1, client_ctx->server_address_count,
                force_reconnect ? " (active resolver unhealthy)" : "");
    } else {
        fprintf(stderr,
                "Client using resolver index=%zu/%zu as preferred path; it will become main on the next reconnect\n",
                resolver_index + 1, client_ctx->server_address_count);
    }

    slipstream_client_apply_resolver_path_priorities(client_ctx, resolver_index);
    if (client_ctx->cnx != NULL) {
        picoquic_reinsert_by_wake_time(client_ctx->cnx->quic, client_ctx->cnx, current_time);
    }
}

static void slipstream_client_finish_resolver_selection(slipstream_client_ctx_t* client_ctx,
                                                        uint64_t current_time) {
    if (!client_ctx->resolver_selection_in_progress) {
        return;
    }

    slipstream_client_discover_resolver_paths(client_ctx);

    bool has_sample = false;
    size_t best_index = slipstream_client_best_sampled_resolver(client_ctx, &has_sample, current_time);
    if (!has_sample || best_index >= client_ctx->server_address_count) {
        best_index = client_ctx->active_resolver_index;
    } else if (best_index != client_ctx->active_resolver_index &&
        client_ctx->active_resolver_index < client_ctx->server_address_count) {
        uint64_t best_score =
            slipstream_client_resolver_score(client_ctx, best_index, current_time, false);
        uint64_t active_score =
            slipstream_client_resolver_score(client_ctx, client_ctx->active_resolver_index, current_time, false);
        if (active_score != UINT64_MAX &&
            best_score + SLIPSTREAM_RESOLVER_SWITCH_SCORE_MARGIN_US >= active_score) {
            best_index = client_ctx->active_resolver_index;
        }
    }

    slipstream_client_log_resolver_selection(client_ctx, best_index, has_sample, current_time);
    client_ctx->resolver_selection_in_progress = false;
    client_ctx->resolver_selection_done = true;
    client_ctx->resolver_reselection_next_at = current_time + SLIPSTREAM_RESOLVER_RESELECTION_INTERVAL_US;

    if (has_sample && best_index != client_ctx->active_resolver_index) {
        slipstream_client_select_resolver(client_ctx, best_index, current_time, false, "better path");
    } else {
        client_ctx->next_resolver_index = client_ctx->active_resolver_index;
        slipstream_client_apply_resolver_path_priorities(client_ctx, best_index);
        if (client_ctx->cnx != NULL) {
            picoquic_reinsert_by_wake_time(client_ctx->cnx->quic, client_ctx->cnx, current_time);
        }
    }
}

static void slipstream_client_maybe_finish_resolver_selection(slipstream_client_ctx_t* client_ctx,
                                                              uint64_t current_time) {
    if (!client_ctx->resolver_selection_in_progress || !client_ctx->ready || client_ctx->cnx == NULL) {
        return;
    }

    slipstream_client_discover_resolver_paths(client_ctx);
    bool all_sampled = slipstream_client_all_resolvers_sampled(client_ctx);
    bool min_elapsed =
        current_time - client_ctx->resolver_selection_started_at >= SLIPSTREAM_RESOLVER_SELECTION_MIN_US;
    bool timed_out = current_time >= client_ctx->resolver_selection_deadline_at;

    if ((all_sampled && min_elapsed) || timed_out) {
        slipstream_client_finish_resolver_selection(client_ctx, current_time);
    }
}

static void slipstream_client_note_resolver_path_event(slipstream_client_ctx_t* client_ctx,
                                                       picoquic_cnx_t* cnx,
                                                       uint64_t unique_path_id) {
    size_t resolver_index = slipstream_client_find_resolver_by_path_id(client_ctx, cnx, unique_path_id);
    if (resolver_index == SIZE_MAX) {
        return;
    }

    slipstream_client_record_resolver_path_id(client_ctx, resolver_index, unique_path_id);
    if (client_ctx->resolver_selection_in_progress) {
        (void)picoquic_subscribe_to_quality_update_per_path(cnx, unique_path_id, 0,
                                                            SLIPSTREAM_RESOLVER_SELECTION_RTT_DELTA_US);
    }
    (void)slipstream_client_sample_resolver_latency(client_ctx, resolver_index, unique_path_id);
    slipstream_client_maybe_finish_resolver_selection(client_ctx, picoquic_current_time());
}

static bool slipstream_client_should_log_resolver_quality(slipstream_client_ctx_t* client_ctx,
                                                          picoquic_cnx_t* cnx,
                                                          uint64_t unique_path_id,
                                                          uint64_t current_time) {
    size_t resolver_index = slipstream_client_find_resolver_by_path_id(client_ctx, cnx, unique_path_id);
    if (resolver_index == SIZE_MAX || client_ctx->resolver_quality_log_next_at == NULL) {
        return true;
    }

    if (current_time < client_ctx->resolver_quality_log_next_at[resolver_index]) {
        return false;
    }
    client_ctx->resolver_quality_log_next_at[resolver_index] =
        current_time + SLIPSTREAM_RESOLVER_QUALITY_LOG_INTERVAL_US;
    return true;
}

static void slipstream_client_start_resolver_selection(slipstream_client_ctx_t* client_ctx,
                                                       picoquic_cnx_t* cnx,
                                                       uint64_t current_time) {
    if (client_ctx->server_address_count <= 1 ||
        client_ctx->resolver_selection_in_progress || client_ctx->resolver_path_ids == NULL ||
        client_ctx->active_resolver_index >= client_ctx->server_address_count ||
        cnx == NULL || cnx->path[0] == NULL) {
        return;
    }

    client_ctx->resolver_selection_in_progress = true;
    client_ctx->resolver_selection_done = false;
    client_ctx->resolver_selection_started_at = current_time;
    client_ctx->resolver_selection_deadline_at = current_time + SLIPSTREAM_RESOLVER_SELECTION_TIMEOUT_US;
    client_ctx->resolver_reselection_next_at = current_time + SLIPSTREAM_RESOLVER_RESELECTION_INTERVAL_US;

    uint64_t active_path_id = cnx->path[0]->unique_path_id;
    slipstream_client_record_resolver_path_id(client_ctx, client_ctx->active_resolver_index, active_path_id);
    (void)slipstream_client_sample_resolver_latency(client_ctx, client_ctx->active_resolver_index, active_path_id);
    picoquic_subscribe_to_quality_update(cnx, 0, SLIPSTREAM_RESOLVER_SELECTION_RTT_DELTA_US);
    slipstream_client_discover_resolver_paths(client_ctx);

    fprintf(stderr,
            "Client resolver selection started: resolvers=%zu test-window=%.1fs timeout=%.1fs\n",
            client_ctx->server_address_count,
            (double)SLIPSTREAM_RESOLVER_SELECTION_MIN_US / 1000000.0,
            (double)SLIPSTREAM_RESOLVER_SELECTION_TIMEOUT_US / 1000000.0);
}

static bool slipstream_client_resolver_health_bad(const slipstream_client_ctx_t* client_ctx,
                                                  size_t resolver_index) {
    if (resolver_index >= client_ctx->server_address_count ||
        client_ctx->resolver_loss_permille == NULL) {
        return false;
    }

    uint64_t loss_permille = client_ctx->resolver_loss_permille[resolver_index];
    bool cwin_collapsed = client_ctx->resolver_cwin != NULL &&
        client_ctx->resolver_cwin[resolver_index] > 0 &&
        client_ctx->resolver_cwin[resolver_index] <= SLIPSTREAM_RESOLVER_CWIN_COLLAPSED_BYTES;

    return loss_permille >= SLIPSTREAM_RESOLVER_ACTIVE_BAD_LOSS_PERMILLE ||
        (cwin_collapsed && loss_permille > 0);
}

static void slipstream_client_maybe_failover_active_resolver(slipstream_client_ctx_t* client_ctx,
                                                             uint64_t current_time) {
    if (client_ctx->server_address_count <= 1 || client_ctx->reconnect_pending ||
        client_ctx->active_resolver_index >= client_ctx->server_address_count ||
        current_time < client_ctx->resolver_failover_next_at) {
        return;
    }

    size_t active_index = client_ctx->active_resolver_index;
    if (!slipstream_client_resolver_health_bad(client_ctx, active_index)) {
        client_ctx->active_resolver_bad_windows = 0;
        return;
    }

    if (client_ctx->active_resolver_bad_windows < UINT8_MAX) {
        client_ctx->active_resolver_bad_windows++;
    }
    if (client_ctx->active_resolver_bad_windows < SLIPSTREAM_RESOLVER_ACTIVE_BAD_WINDOWS) {
        return;
    }

    if (client_ctx->resolver_unhealthy_until != NULL) {
        client_ctx->resolver_unhealthy_until[active_index] =
            current_time + SLIPSTREAM_RESOLVER_UNHEALTHY_COOLDOWN_US;
    }

    bool has_sample = false;
    size_t best_index = slipstream_client_best_sampled_resolver(client_ctx, &has_sample, current_time);
    if (!has_sample || best_index == active_index || best_index >= client_ctx->server_address_count) {
        fprintf(stderr,
                "Client active resolver unhealthy, but no verified better resolver is available yet; keeping current resolver\n");
        client_ctx->active_resolver_bad_windows = 0;
        return;
    }

    uint64_t loss_permille = client_ctx->resolver_loss_permille == NULL ? 0 :
        client_ctx->resolver_loss_permille[active_index];
    uint64_t cwin = client_ctx->resolver_cwin == NULL ? 0 :
        client_ctx->resolver_cwin[active_index];
    size_t mtu = client_ctx->resolver_send_mtu == NULL ? client_query_payload_budget :
        slipstream_client_clamp_adaptive_mtu(client_ctx->resolver_send_mtu[active_index]);
    fprintf(stderr,
            "Client active resolver unhealthy: index=%zu/%zu loss=%.1f%% cwin=%llu mtu=%zu; trying resolver index=%zu/%zu\n",
            active_index + 1, client_ctx->server_address_count,
            (double)loss_permille / 10.0,
            (unsigned long long)cwin,
            mtu,
            best_index + 1, client_ctx->server_address_count);

    client_ctx->active_resolver_bad_windows = 0;
    client_ctx->resolver_failover_next_at = current_time + SLIPSTREAM_RESOLVER_FAILOVER_MIN_INTERVAL_US;
    slipstream_client_select_resolver(client_ctx, best_index, current_time, false, "active unhealthy");
}

static void slipstream_client_run_resolver_health_check(slipstream_client_ctx_t* client_ctx,
                                                        uint64_t current_time) {
    if (!client_ctx->ready || client_ctx->cnx == NULL) {
        return;
    }
    if (client_ctx->resolver_health_next_at != 0 &&
        current_time < client_ctx->resolver_health_next_at) {
        return;
    }
    client_ctx->resolver_health_next_at = current_time + SLIPSTREAM_RESOLVER_HEALTH_CHECK_INTERVAL_US;

    if (client_ctx->cnx->path[0] != NULL &&
        client_ctx->active_resolver_index < client_ctx->server_address_count) {
        uint64_t active_path_id = client_ctx->cnx->path[0]->unique_path_id;
        slipstream_client_record_resolver_path_id(client_ctx, client_ctx->active_resolver_index, active_path_id);
        (void)slipstream_client_sample_resolver_latency(client_ctx, client_ctx->active_resolver_index,
                                                        active_path_id);
    }

    slipstream_client_discover_resolver_paths(client_ctx);
    slipstream_client_maybe_finish_resolver_selection(client_ctx, current_time);
    if (!client_ctx->resolver_selection_in_progress &&
        (client_ctx->resolver_reselection_next_at == 0 ||
         current_time >= client_ctx->resolver_reselection_next_at)) {
        slipstream_client_start_resolver_selection(client_ctx, client_ctx->cnx, current_time);
    }
    slipstream_client_maybe_failover_active_resolver(client_ctx, current_time);
}

static int slipstream_client_connect_resolver(picoquic_quic_t* quic, slipstream_client_ctx_t* client_ctx,
                                              size_t resolver_index) {
    if (resolver_index >= client_ctx->server_address_count) {
        return -1;
    }

    picoquic_cnx_t* cnx = NULL;
    char resolver_text[NI_MAXHOST + NI_MAXSERV + 8];
    fprintf(stderr, "Client resolver connect attempt: index=%zu/%zu resolver=%s\n",
            resolver_index + 1, client_ctx->server_address_count,
            slipstream_format_sockaddr(&client_ctx->server_addresses[resolver_index].server_address,
                                       resolver_text, sizeof(resolver_text)));

    int ret = slipstream_connect(&client_ctx->server_addresses[resolver_index].server_address, quic, &cnx, client_ctx);
    if (ret == 0) {
        client_ctx->active_resolver_index = resolver_index;
        client_ctx->next_resolver_index = slipstream_client_next_resolver_index(client_ctx, resolver_index);
        client_ctx->connect_started_at = picoquic_current_time();
        slipstream_client_apply_resolver_connect_mtu(client_ctx, resolver_index);
    }
    return ret;
}

static int slipstream_client_connect_next_resolver(picoquic_quic_t* quic, slipstream_client_ctx_t* client_ctx) {
    if (client_ctx->server_address_count == 0) {
        fprintf(stderr, "Client has no resolver addresses configured\n");
        return -1;
    }

    size_t start_index = client_ctx->next_resolver_index;
    if (start_index >= client_ctx->server_address_count) {
        start_index = 0;
    }

    int last_ret = -1;
    for (size_t attempt = 0; attempt < client_ctx->server_address_count; attempt++) {
        size_t resolver_index = (start_index + attempt) % client_ctx->server_address_count;
        last_ret = slipstream_client_connect_resolver(quic, client_ctx, resolver_index);
        if (last_ret == 0) {
            return 0;
        }
        client_ctx->next_resolver_index = slipstream_client_next_resolver_index(client_ctx, resolver_index);
    }

    return last_ret;
}

static void slipstream_client_connection_lost(slipstream_client_ctx_t* client_ctx) {
    if (should_shutdown || client_ctx->reconnect_pending) {
        return;
    }
    client_ctx->ready = false;
    client_ctx->connect_started_at = 0;
    char resolver_text[NI_MAXHOST + NI_MAXSERV + 8];
    if (client_ctx->active_resolver_index < client_ctx->server_address_count) {
        fprintf(stderr, "Client QUIC connection lost: resolver=%s index=%zu/%zu\n",
                slipstream_format_sockaddr(&client_ctx->server_addresses[client_ctx->active_resolver_index].server_address,
                                           resolver_text, sizeof(resolver_text)),
                client_ctx->active_resolver_index + 1, client_ctx->server_address_count);
    } else {
        fprintf(stderr, "Client QUIC connection lost\n");
    }
    slipstream_client_schedule_reconnect(client_ctx, picoquic_current_time());
}

static void slipstream_client_check_connect_timeout(slipstream_client_ctx_t* client_ctx, uint64_t current_time) {
    if (should_shutdown || client_ctx->ready || client_ctx->reconnect_pending || client_ctx->cnx == NULL ||
        client_ctx->connect_started_at == 0 ||
        current_time - client_ctx->connect_started_at < SLIPSTREAM_RESOLVER_CONNECT_TIMEOUT_US) {
        return;
    }

    char resolver_text[NI_MAXHOST + NI_MAXSERV + 8];
    if (client_ctx->active_resolver_index < client_ctx->server_address_count) {
        fprintf(stderr, "Client QUIC connect timed out: resolver=%s index=%zu/%zu; trying next resolver\n",
                slipstream_format_sockaddr(&client_ctx->server_addresses[client_ctx->active_resolver_index].server_address,
                                           resolver_text, sizeof(resolver_text)),
                client_ctx->active_resolver_index + 1, client_ctx->server_address_count);
        slipstream_client_note_resolver_connect_timeout(client_ctx, client_ctx->active_resolver_index, current_time);
    } else {
        fprintf(stderr, "Client QUIC connect timed out; trying next resolver\n");
    }

    picoquic_delete_cnx(client_ctx->cnx);
    client_ctx->cnx = NULL;
    client_ctx->connect_started_at = 0;
    slipstream_client_schedule_reconnect(client_ctx, current_time);
}

static int slipstream_client_reconnect(picoquic_quic_t* quic, slipstream_client_ctx_t* client_ctx) {
    if (client_ctx->resolver_switch_pending && !client_ctx->resolver_failover_pending &&
        client_ctx->first_stream != NULL) {
        fprintf(stderr,
                "Client resolver switch deferred because local TCP streams are active; preferred resolver index=%zu/%zu\n",
                client_ctx->next_resolver_index + 1, client_ctx->server_address_count);
        client_ctx->active_resolver_index = client_ctx->next_resolver_index;
        client_ctx->reconnect_pending = false;
        client_ctx->resolver_switch_pending = false;
        client_ctx->resolver_failover_pending = false;
        slipstream_client_apply_resolver_path_priorities(client_ctx, client_ctx->active_resolver_index);
        return 0;
    }
    client_ctx->resolver_switch_pending = false;
    client_ctx->resolver_failover_pending = false;

    while (client_ctx->first_stream != NULL) {
        slipstream_client_free_stream_ctx(client_ctx, client_ctx->first_stream);
    }

    if (client_ctx->cnx != NULL) {
        picoquic_delete_cnx(client_ctx->cnx);
        client_ctx->cnx = NULL;
    }

    client_ctx->ready = false;
    slipstream_client_reset_paths(client_ctx);
    slipstream_client_use_legacy_queries(client_ctx);
    slipstream_client_set_query_mtu(quic, client_query_payload_budget);

    fprintf(stderr, "Client reconnect attempt starting: next-resolver=%zu/%zu\n",
            client_ctx->next_resolver_index + 1, client_ctx->server_address_count);
    int ret = slipstream_client_connect_next_resolver(quic, client_ctx);
    if (ret == 0) {
        client_ctx->reconnect_pending = false;
        fprintf(stderr, "Client reconnect attempt created; waiting for QUIC confirmation\n");
        return 0;
    }

    client_ctx->cnx = NULL;
    fprintf(stderr, "Client reconnect attempt failed, ret = %d\n", ret);
    slipstream_client_schedule_reconnect(client_ctx, picoquic_current_time());
    return ret;
}

void slipstream_client_mark_active_pass(slipstream_client_ctx_t* client_ctx) {
    if (!client_ctx->ready || client_ctx->cnx == NULL) {
        return;
    }

    slipstream_client_stream_ctx_t* stream_ctx = client_ctx->first_stream;

    while (stream_ctx != NULL) {
        if (stream_ctx->set_active && stream_ctx->fd != -1) {
            if (stream_ctx->stream_id == -1) {
                stream_ctx->stream_id = picoquic_get_next_local_stream_id(client_ctx->cnx, 0);
                DBG_PRINTF("[%lu:%d] assigned stream id", stream_ctx->stream_id, stream_ctx->fd);
                fprintf(stderr, "Client stream opened: id=%llu fd=%d\n",
                        (unsigned long long)stream_ctx->stream_id, stream_ctx->fd);
            }
            stream_ctx->set_active = 0;
            DBG_PRINTF("[%lu:%d] activate: stream", stream_ctx->stream_id, stream_ctx->fd);
            picoquic_mark_active_stream(client_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
            slipstream_client_schedule_active_poll(client_ctx, picoquic_current_time());
        }
        stream_ctx = stream_ctx->next_stream;
    }
}

void slipstream_add_paths(slipstream_client_ctx_t* client_ctx) {
    picoquic_cnx_t* cnx = client_ctx->cnx;
    if (cnx == NULL || client_ctx->server_address_count <= 1) {
        return;
    }
    if (!cnx->is_multipath_enabled || cnx->path[0] == NULL) {
        if (!client_ctx->resolver_paths_unavailable_logged) {
            fprintf(stderr,
                    "Client resolver multipath unavailable; using primary resolver only (secondary resolvers=%zu)\n",
                    client_ctx->server_address_count - 1);
            client_ctx->resolver_paths_unavailable_logged = true;
        }
        return;
    }

    uint64_t current_time = picoquic_current_time();
    // add rest of the resolvers
    for (size_t offset = 1; offset < client_ctx->server_address_count; offset++) {
        size_t i = (client_ctx->active_resolver_index + offset) % client_ctx->server_address_count;
        address_t* slipstream_path = &client_ctx->server_addresses[i];
        if (slipstream_path->added) {
            continue;
        }
        if (client_ctx->resolver_probe_next_at != NULL &&
            current_time < client_ctx->resolver_probe_next_at[i]) {
            continue;
        }

        // if (current_time - cnx->start_time < 10000000) {
        //     DBG_PRINTF("Can't add path yet", NULL);
        //     continue;
        // }

        char addr_text[NI_MAXHOST + NI_MAXSERV + 8];
        fprintf(stderr, "Client probing resolver path: %s\n",
                slipstream_format_sockaddr(&slipstream_path->server_address, addr_text, sizeof(addr_text)));
        int path_id = -2;
        int probe_ret = picoquic_probe_new_path_ex(cnx, (struct sockaddr*)&slipstream_path->server_address, (struct sockaddr*)&cnx->path[0]->local_addr, 0, current_time, 0, &path_id);
        if (path_id < 0) {
            uint64_t delay = SLIPSTREAM_RESOLVER_PROBE_INITIAL_DELAY_US;
            if (client_ctx->resolver_probe_delay != NULL && client_ctx->resolver_probe_delay[i] != 0) {
                delay = client_ctx->resolver_probe_delay[i];
            }
            if (client_ctx->resolver_probe_next_at != NULL) {
                client_ctx->resolver_probe_next_at[i] = current_time + delay;
            }
            if (client_ctx->resolver_probe_delay != NULL) {
                client_ctx->resolver_probe_delay[i] = delay * 2;
                if (client_ctx->resolver_probe_delay[i] > SLIPSTREAM_RESOLVER_PROBE_MAX_DELAY_US) {
                    client_ctx->resolver_probe_delay[i] = SLIPSTREAM_RESOLVER_PROBE_MAX_DELAY_US;
                }
            }
            DBG_PRINTF("Failed adding path", NULL);
            fprintf(stderr, "Client resolver path probe failed: %s ret=%d; retry in %.1f seconds\n",
                    addr_text, probe_ret, (double)delay / 1000000.0);
            continue;
        }
        DBG_PRINTF("Added path", NULL);
        uint64_t unique_path_id = SLIPSTREAM_RESOLVER_PATH_ID_UNKNOWN;
        if (path_id >= 0 && path_id < cnx->nb_paths && cnx->path[path_id] != NULL) {
            unique_path_id = cnx->path[path_id]->unique_path_id;
            slipstream_client_record_resolver_path_id(client_ctx, i, unique_path_id);
            slipstream_client_apply_resolver_mtu(client_ctx, i, unique_path_id, "applied");
            if (client_ctx->resolver_selection_in_progress) {
                (void)picoquic_subscribe_to_quality_update_per_path(
                    cnx, unique_path_id, 0, SLIPSTREAM_RESOLVER_SELECTION_RTT_DELTA_US);
            }
        }
        fprintf(stderr, "Client resolver path added: %s path=%d id=%llu\n",
                addr_text, path_id, (unsigned long long)unique_path_id);

        picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time);
        slipstream_path->added = true;
        if (client_ctx->resolver_probe_next_at != NULL) {
            client_ctx->resolver_probe_next_at[i] = 0;
        }
        if (client_ctx->resolver_probe_delay != NULL) {
            client_ctx->resolver_probe_delay[i] = 0;
        }
    }
}

int slipstream_client_sockloop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
                                   void* callback_ctx, void* callback_arg) {
    slipstream_client_ctx_t* client_ctx = callback_ctx;

    if (client_ctx->closed) {
        return 0;
    }

    switch (cb_mode) {
    case picoquic_packet_loop_before_select:
        {
            uint64_t current_time = picoquic_current_time();
            slipstream_client_check_connect_timeout(client_ctx, current_time);
        }

        if (should_shutdown) {
            // Iterate and close all connections
            picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic);
            bool has_unclosed = false;
            while (cnx != NULL) {
                DBG_PRINTF("CNX state: %d", cnx->cnx_state);
                if (cnx->cnx_state != picoquic_state_disconnected) {
                    has_unclosed = true;
                }

                picoquic_close(cnx, 0); // 0 = no error, or use appropriate error code

                if (cnx->cnx_state == picoquic_state_draining) {
                    picoquic_connection_disconnect(cnx);
                }

                cnx = picoquic_get_next_cnx(cnx);
            }

            if (!has_unclosed) {
                DBG_PRINTF("All connections closed, shutting down.", NULL);
                return -1;
            }
            break;
        }

        if (client_ctx->cnx != NULL && client_ctx->cnx->cnx_state == picoquic_state_disconnected) {
            slipstream_client_connection_lost(client_ctx);
        }

        if (client_ctx->reconnect_pending && picoquic_current_time() >= client_ctx->reconnect_at) {
            (void)slipstream_client_reconnect(quic, client_ctx);
        }

        if (client_ctx->ready) {
            uint64_t current_time = picoquic_current_time();
            slipstream_add_paths(client_ctx);
            slipstream_client_run_resolver_health_check(client_ctx, current_time);
        }
        slipstream_client_mark_active_pass(client_ctx);
        slipstream_client_schedule_active_poll(client_ctx, picoquic_current_time());

        break;
    case picoquic_packet_loop_wake_up:
        if (callback_ctx == NULL) {
            return 0;
        }

        slipstream_client_mark_active_pass(client_ctx);
        slipstream_client_schedule_active_poll(client_ctx, picoquic_current_time());

        break;
    case picoquic_packet_loop_after_send:
        if (callback_ctx == NULL) {
            return 0;
        }

        if (client_ctx->cnx != NULL && client_ctx->cnx->cnx_state == picoquic_state_disconnected) {
            slipstream_client_connection_lost(client_ctx);
        }
    default:
        break;
    }

    return 0;
}

typedef struct st_slipstream_client_poller_args {
    int fd;
    picoquic_cnx_t* cnx;
    slipstream_client_ctx_t* client_ctx;
    slipstream_client_stream_ctx_t* stream_ctx;
} slipstream_client_poller_args;

static void* slipstream_client_poller(void* arg);

static void slipstream_client_arm_poller(picoquic_cnx_t* cnx,
                                         slipstream_client_ctx_t* client_ctx,
                                         slipstream_client_stream_ctx_t* stream_ctx) {
    if (!__sync_bool_compare_and_swap(&stream_ctx->poller_active, 0, 1)) {
        return;
    }

    slipstream_client_poller_args* args = malloc(sizeof(slipstream_client_poller_args));
    if (args == NULL) {
        __sync_lock_release(&stream_ctx->poller_active);
        return;
    }
    args->fd = stream_ctx->fd;
    args->cnx = cnx;
    args->client_ctx = client_ctx;
    args->stream_ctx = stream_ctx;

    slipstream_client_stream_retain(stream_ctx);
    pthread_t thread;
    if (pthread_create(&thread, NULL, slipstream_client_poller, args) != 0) {
        perror("pthread_create() failed for client poller");
        slipstream_client_stream_release(stream_ctx);
        __sync_lock_release(&stream_ctx->poller_active);
        free(args);
        return;
    }

#ifdef __APPLE__
    pthread_setname_np("slipstream_client_poller");
#else
    pthread_setname_np(thread, "slipstream_client_poller");
#endif
    pthread_detach(thread);
}

static void* slipstream_client_poller(void* arg) {
    slipstream_client_poller_args* args = arg;
    slipstream_client_stream_ctx_t* stream_ctx = args->stream_ctx;

    while (1) {
        struct pollfd fds;
        fds.fd = args->fd;
        fds.events = POLLIN;
        fds.revents = 0;

        /* add timeout handlilng */
        int ret = poll(&fds, 1, 1000);
        if (ret < 0) {
            perror("poll() failed");
            break;
        }
        if (ret == 0) {
            continue;
        }

        if (stream_ctx->fd != -1) {
            stream_ctx->set_active = 1;
        }

        ret = picoquic_wake_up_network_thread(args->client_ctx->thread_ctx);
        if (ret != 0) {
            fprintf(stderr, "poll: could not wake up network thread, ret = %d\n", ret);
        }
        DBG_PRINTF("[%lu:%d] wakeup", stream_ctx->stream_id, args->fd);

        break;
    }

    __sync_lock_release(&stream_ctx->poller_active);
    slipstream_client_stream_release(stream_ctx);
    free(args);
    pthread_exit(NULL);
}

typedef struct st_slipstream_client_accepter_args {
    int fd;
    slipstream_client_ctx_t* client_ctx;
    slipstream_client_stream_ctx_t* stream_ctx;
    picoquic_network_thread_ctx_t* thread_ctx;
} slipstream_client_accepter_args;

void* slipstream_client_accepter(void* arg) {
    slipstream_client_accepter_args* args = arg;

    while (1) {
        // Accept incoming client connection
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(args->fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept() failed");
            break;
        }

        char client_ip_str[INET_ADDRSTRLEN]; // Buffer for the IP address string

        // Convert binary IP address to string representation
        if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, sizeof(client_ip_str)) == NULL) {
            perror("inet_ntop failed");
            close(client_sock); // Close socket if IP conversion fails
            continue; // Or break, depending on desired error handling
        }

        // Convert port number from network byte order to host byte order
        uint16_t client_port = ntohs(client_addr.sin_port);

        // Print the connection details
        DBG_PRINTF("Accepted connection from %s:%u on socket %d", client_ip_str, client_port, client_sock);
        fprintf(stderr, "Client accepted local TCP connection: peer=%s:%u fd=%d\n",
                client_ip_str, client_port, client_sock);
        if (!args->client_ctx->ready || args->client_ctx->cnx == NULL) {
            fprintf(stderr, "Client accepted local TCP connection while QUIC tunnel is not ready; fd=%d will wait\n",
                    client_sock);
        }
        // --- End printing section ---

        slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(args->client_ctx, client_sock);
        if (stream_ctx == NULL) {
            fprintf(stderr, "Could not initiate stream for %d\n", client_sock);
            break;
        }

        stream_ctx->set_active = 1;

        int ret = picoquic_wake_up_network_thread(args->thread_ctx);
        if (ret != 0) {
            fprintf(stderr, "accept: could not wake up network thread, ret = %d\n", ret);
            pthread_exit(NULL);
        }

        DBG_PRINTF("[%lu:%d] accept: connection and wakeup", stream_ctx->stream_id, client_sock);
    }

    free(args);
    pthread_exit(NULL);
}

static int slipstream_client_send_all(int fd, const uint8_t* bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t bytes_sent = send(fd, bytes + offset, length - offset, MSG_NOSIGNAL);
        if (bytes_sent > 0) {
            offset += (size_t)bytes_sent;
            continue;
        }
        if (bytes_sent < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

int slipstream_client_callback(picoquic_cnx_t* cnx,
                               uint64_t stream_id, uint8_t* bytes, size_t length,
                               picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx) {
    int ret = 0;
    slipstream_client_ctx_t* client_ctx = (slipstream_client_ctx_t*)callback_ctx;
    slipstream_client_stream_ctx_t* stream_ctx = (slipstream_client_stream_ctx_t*)v_stream_ctx;

    if (client_ctx == NULL) {
        /* This should never happen, because the callback context for the client is initialized
         * when creating the client connection. */
        return -1;
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        if (stream_ctx == NULL) {
            if ((stream_id & 3) == 3 && length > 0) {
                slipstream_client_process_control_stream(cnx, client_ctx, bytes, length);
            }
            /* This is unexpected, as all contexts were declared when initializing the
             * connection. */
            return 0;
        }

        // printf("[%lu:%d] quic_recv->send %lu bytes\n", stream_id, stream_ctx->fd, length);
        if (length > 0) {
            if (slipstream_client_send_all(stream_ctx->fd, bytes, length) != 0) {
                if (errno == EPIPE) {
                    /* Connection closed */
                    DBG_PRINTF("[%lu:%d] send: closed stream", stream_id, stream_ctx->fd);

                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                    return 0;
                }
                if (errno == EAGAIN) {
                    /* TODO: this is bad because we don't have a way to backpressure */
                }

                fprintf(stderr, "[%lu:%d] send: error: %s (%d)\n", stream_id, stream_ctx->fd, strerror(errno), errno);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
        }
        if (fin_or_event == picoquic_callback_stream_fin) {
            DBG_PRINTF("[%lu:%d] fin", stream_id, stream_ctx->fd);
            fprintf(stderr, "Client stream finished: id=%llu fd=%d\n",
                    (unsigned long long)stream_id, stream_ctx->fd);
            slipstream_client_free_stream_ctx(client_ctx, stream_ctx);
        }
        break;
    case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
        /* Mark stream as abandoned, close the file, etc. */
        picoquic_reset_stream(cnx, stream_id, 0);
        /* Fall through */
    case picoquic_callback_stream_reset: /* Server reset stream #x */
        if (stream_ctx == NULL) {
            /* This is unexpected, as all contexts were declared when initializing the
             * connection. */
        }
        else {
            DBG_PRINTF("[%lu:%d] stream reset", stream_id, stream_ctx->fd);
            fprintf(stderr, "Client stream reset: id=%llu fd=%d\n",
                    (unsigned long long)stream_id, stream_ctx->fd);

            slipstream_client_free_stream_ctx(client_ctx, stream_ctx);
            picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close: /* Received connection close */
    case picoquic_callback_application_close: /* Received application close */
        DBG_PRINTF("%s", "Connection closed, reconnecting");
        fprintf(stderr, "Client QUIC %s received, reconnecting\n",
                slipstream_client_event_name(fin_or_event));
        slipstream_client_connection_lost(client_ctx);
        break;
    case picoquic_callback_prepare_to_send:
        /* Active sending API */
        if (stream_ctx == NULL) {
            /* This should never happen */
        }
        else if (stream_ctx->fd == -1) {
            (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        else {
            int length_available;
            ret = ioctl(stream_ctx->fd, FIONREAD, &length_available);
            // printf("[%lu:%d] recv->quic_send (available %d)\n", stream_id, stream_ctx->fd, length_available);
            if (ret < 0) {
                fprintf(stderr, "[%lu:%d] ioctl error: %s (%d)\n", stream_id, stream_ctx->fd, strerror(errno), errno);
                /* TODO: why would it return an error? */
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                break;
            }
            ret = 0;

            size_t length_to_read = MIN((size_t)length, (size_t)length_available);
            if (length_to_read == 0) {
                char a;
                errno = 0;
                ssize_t bytes_read = recv(stream_ctx->fd, &a, 1, MSG_PEEK | MSG_DONTWAIT);
                // printf("[%lu:%d] recv->quic_send empty read %d bytes\n", stream_id, stream_ctx->fd, bytes_read);
                if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    // printf("[%lu:%d] recv->quic_send empty errno set: %s\n", stream_id, stream_ctx->fd, strerror(errno));
                    /* No bytes available, wait for next event */
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
                    DBG_PRINTF("[%lu:%d] recv->quic_send: empty, disactivate", stream_id, stream_ctx->fd);
                    slipstream_client_arm_poller(cnx, client_ctx, stream_ctx);
                    return 0;
                }
                if (bytes_read == 0) {
                    DBG_PRINTF("[%lu:%d] recv: closed stream", stream_id, stream_ctx->fd);
                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                    return 0;
                }
                if (bytes_read > 0) {
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
                    picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
                    return 0;
                }
                if (bytes_read < 0) {
                    fprintf(stderr, "[%lu:%d] recv: error: %s (%d)\n", stream_id, stream_ctx->fd, strerror(errno), errno);
                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                }
                return 0;
            }

            // printf("[%lu:%d] recv->quic_send recv %d bytes into quic\n", stream_id, stream_ctx->fd, length_to_read);
            uint8_t stack_buffer[PICOQUIC_MAX_PACKET_SIZE];
            if (length_to_read > sizeof(stack_buffer)) {
                length_to_read = sizeof(stack_buffer);
            }
            ssize_t bytes_read = recv(stream_ctx->fd, stack_buffer, length_to_read, MSG_DONTWAIT);
            // printf("[%lu:%d] recv->quic_send recv done %d bytes into quic\n", stream_id, stream_ctx->fd, bytes_read);
            if (bytes_read == 0) {
                DBG_PRINTF("Closed connection on sock %d on recv", stream_ctx->fd);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                return 0;
            }
            if (bytes_read < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
                    slipstream_client_arm_poller(cnx, client_ctx, stream_ctx);
                    return 0;
                }
                fprintf(stderr, "[%lu:%d] recv: %s (%d)\n", stream_id, stream_ctx->fd, strerror(errno), errno);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
            uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, (size_t)bytes_read, 0, 1);
            if (buffer == NULL) {
                /* Should never happen according to callback spec. */
                break;
            }
            memcpy(buffer, stack_buffer, (size_t)bytes_read);
        }
        break;
    case picoquic_callback_almost_ready:
        fprintf(stderr, "Client QUIC connection completed, almost ready\n");
        break;
    case picoquic_callback_ready:
        fprintf(stderr, "Client QUIC connection confirmed\n");
        client_ctx->ready = true;
        client_ctx->reconnect_delay = 1000000;
        client_ctx->connect_started_at = 0;
        client_ctx->next_resolver_index = client_ctx->active_resolver_index;
        char resolver_text[NI_MAXHOST + NI_MAXSERV + 8];
        fprintf(stderr, "Client active resolver: index=%zu/%zu resolver=%s\n",
                client_ctx->active_resolver_index + 1, client_ctx->server_address_count,
                slipstream_format_sockaddr(&client_ctx->server_addresses[client_ctx->active_resolver_index].server_address,
                                           resolver_text, sizeof(resolver_text)));
        fprintf(stderr, "Client QUIC multipath: negotiated=%s paths=%d resolvers=%zu\n",
                cnx->is_multipath_enabled ? "yes" : "no",
                cnx->nb_paths,
                client_ctx->server_address_count);
        slipstream_client_log_path_event(cnx, 0, "primary ready");
        if (cnx->path[0] != NULL) {
            uint64_t active_path_id = cnx->path[0]->unique_path_id;
            slipstream_client_record_resolver_path_id(client_ctx, client_ctx->active_resolver_index, active_path_id);
            slipstream_client_apply_resolver_mtu(client_ctx, client_ctx->active_resolver_index,
                                                 active_path_id, "applied");
        }
        picoquic_subscribe_to_quality_update(cnx, 0, SLIPSTREAM_RESOLVER_SELECTION_RTT_DELTA_US);
        slipstream_client_start_resolver_selection(client_ctx, cnx, picoquic_current_time());
        slipstream_add_paths(client_ctx);
        slipstream_client_schedule_active_poll(client_ctx, picoquic_current_time());
        break;
    case picoquic_callback_path_available:
        slipstream_client_log_path_event(cnx, stream_id, "available");
        slipstream_client_note_resolver_path_event(client_ctx, cnx, stream_id);
        break;
    case picoquic_callback_path_suspended:
        slipstream_client_log_path_event(cnx, stream_id, "suspended");
        break;
    case picoquic_callback_path_deleted:
        slipstream_client_forget_resolver_path(client_ctx, stream_id);
        fprintf(stderr, "Client resolver path deleted: id=%llu\n", (unsigned long long)stream_id);
        break;
    case picoquic_callback_path_quality_changed:
    {
        uint64_t current_time = picoquic_current_time();
        slipstream_client_note_resolver_path_event(client_ctx, cnx, stream_id);
        if (slipstream_client_should_log_resolver_quality(client_ctx, cnx, stream_id, current_time)) {
            slipstream_client_log_path_event(cnx, stream_id, "quality changed");
        }
        break;
    }
    case picoquic_callback_app_wakeup:
        if (client_ctx->ready && client_ctx->first_stream != NULL) {
            cnx->is_poll_requested = 1;
            slipstream_client_schedule_active_poll(client_ctx, picoquic_current_time());
        }
        else {
            picoquic_set_app_wake_time(cnx, 0);
        }
        break;
    default:
        /* unexpected -- just ignore. */
        break;
    }

    return ret;
}

static int slipstream_connect(struct sockaddr_storage* server_address,
                                  picoquic_quic_t* quic, picoquic_cnx_t** cnx,
                                  slipstream_client_ctx_t* client_ctx) {
    int ret = 0;
    char const* sni = SLIPSTREAM_SNI;
    uint64_t current_time = picoquic_current_time();

    *cnx = NULL;

    char remote_text[NI_MAXHOST + NI_MAXSERV + 8];

    /* Initialize the callback context and create the connection context.
     * We use minimal options on the client side, keeping the transport
     * parameter values set by default for picoquic. This could be fixed later.
     */
    fprintf(stderr, "Client QUIC connecting: resolver=%s\n",
            slipstream_format_sockaddr(server_address, remote_text, sizeof(remote_text)));

    /* Create a client connection */
    *cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)server_address, current_time, 0, sni, SLIPSTREAM_ALPN, 1);
    if (*cnx == NULL) {
        fprintf(stderr, "Could not create connection context\n");
        return -1;
    }

    /* Document connection in client's context */
    client_ctx->cnx = *cnx;
    /* Set the client callback context */
    picoquic_set_callback(*cnx, slipstream_client_callback, client_ctx);
    picoquic_enable_path_callbacks(*cnx, 1);
    /* Client connection parameters could be set here, before starting the connection. */
    ret = picoquic_start_client_cnx(*cnx);
    if (ret < 0) {
        fprintf(stderr, "Could not activate connection\n");
        picoquic_delete_cnx(*cnx);
        *cnx = NULL;
        client_ctx->cnx = NULL;
        return -1;
    }

    if (client_ctx->keep_alive_interval != 0) {
        picoquic_enable_keep_alive(*cnx, client_ctx->keep_alive_interval * 1000);
    } else {
        picoquic_disable_keep_alive(*cnx);
    }

    /* Printing out the initial CID, which is used to identify log files */
    picoquic_connection_id_t icid = picoquic_get_initial_cnxid(*cnx);
    DBG_PRINTF("%s", "Initial connection ID follows");
    fprintf(stderr, "Client QUIC initial cid: ");
    for (uint8_t i = 0; i < icid.id_len; i++) {
        fprintf(stderr, "%02x", icid.id[i]);
    }
    fprintf(stderr, "\n");

    return ret;
}

int picoquic_slipstream_client(int listen_port, struct st_address_t* server_addresses, size_t server_address_count, const char* domain_name, const char* cc_algo_id, bool gso, const size_t keep_alive_interval) {
    /* Start: start the QUIC process */
    int ret = 0;
    uint64_t current_time = 0;

    if (server_address_count == 0) {
        fprintf(stderr, "Client error: at least one resolver address is required\n");
        return -1;
    }

    client_domain_name = strdup(domain_name);
    client_domain_name_len = strlen(domain_name);
    client_legacy_query_payload_budget = slipstream_client_legacy_query_budget(client_domain_name_len);
    client_packed_query_payload_budget = slipstream_client_packed_query_budget(client_domain_name_len);
    if (client_legacy_query_payload_budget == 0 || client_legacy_query_payload_budget > INT_MAX ||
        client_packed_query_payload_budget == 0 || client_packed_query_payload_budget > INT_MAX) {
        fprintf(stderr, "Domain name is too long for slipstream DNS query encoding: %s\n", domain_name);
        free(client_domain_name);
        client_domain_name = NULL;
        client_domain_name_len = 0;
        return -1;
    }
    client_query_payload_budget = client_legacy_query_payload_budget;
    client_query_label_max = SLIPSTREAM_DNS_LEGACY_ENCODED_LABEL_MAX;
    client_packed_queries_allowed = getenv("SLIPSTREAM_PACKED_QUERIES") != NULL;
    int mtu = (int)client_query_payload_budget;

    /* Create config */
    picoquic_quic_config_t config;
    picoquic_config_init(&config);
    config.nb_connections = 8;
    // config.log_file = "-";
#ifdef BUILD_LOGLIB
    config.qlog_dir = SLIPSTREAM_QLOG_DIR;
#endif
    config.mtu_max = mtu;
    config.initial_send_mtu_ipv4 = mtu;
    config.initial_send_mtu_ipv6 = mtu;
    config.cnx_id_length = SLIPSTREAM_CONNECTION_ID_LEN;
    config.cc_algo_id = cc_algo_id;
    config.multipath_option = 1;
    config.use_long_log = 0;
    config.do_preemptive_repeat = 1;
    config.disable_port_blocking = 1;
    config.enable_sslkeylog = getenv("SSLKEYLOGFILE") != NULL;
    config.alpn = SLIPSTREAM_ALPN;

    fprintf(stderr,
            "Client starting: listen=0.0.0.0:%d domain=%s resolvers=%zu query-mtu=%d response-mtu=%u cid-len=%d dns-query-payload=%zu packed-query-payload=%zu packed-queries=%s cc=%s gso=%s keepalive=%zu\n",
            listen_port, domain_name, server_address_count, mtu, client_response_mtu_max,
            SLIPSTREAM_CONNECTION_ID_LEN, client_query_payload_budget, client_packed_query_payload_budget,
            client_packed_queries_allowed ? "on" : "off", cc_algo_id, gso ? "on" : "off",
            keep_alive_interval);

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    // one connection only, freed in slipstream_client_free_context on picoquic close callback
    slipstream_client_ctx_t client_ctx = {0};
    /* Create QUIC context */
    picoquic_quic_t* quic = picoquic_create_and_configure(&config, slipstream_client_callback, &client_ctx, current_time, NULL);
    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        return -1;
    }
    slipstream_client_advertise_response_mtu(quic);

    picoquic_set_cookie_mode(quic, 0);
    picoquic_set_default_priority(quic, 2);
#ifdef BUILD_LOGLIB
    picoquic_set_qlog(quic, config.qlog_dir);
    debug_printf_push_stream(stderr);
#endif
    picoquic_set_key_log_file_from_env(quic);
    // picoquic_set_textlog(quic, "-");
    // picoquic_set_log_level(quic, 1);
    // TODO: idle timeout?

    /* Parse the server addresses directly */
    client_ctx.server_addresses = server_addresses;
    client_ctx.server_address_count = server_address_count;
    client_ctx.keep_alive_interval = keep_alive_interval;
    client_ctx.reconnect_delay = 1000000;
    client_ctx.next_resolver_index = 0;
    client_ctx.resolver_probe_next_at = calloc(server_address_count, sizeof(*client_ctx.resolver_probe_next_at));
    client_ctx.resolver_probe_delay = calloc(server_address_count, sizeof(*client_ctx.resolver_probe_delay));
    client_ctx.resolver_path_ids = calloc(server_address_count, sizeof(*client_ctx.resolver_path_ids));
    client_ctx.resolver_rtt_us = calloc(server_address_count, sizeof(*client_ctx.resolver_rtt_us));
    client_ctx.resolver_sent = calloc(server_address_count, sizeof(*client_ctx.resolver_sent));
    client_ctx.resolver_lost = calloc(server_address_count, sizeof(*client_ctx.resolver_lost));
    client_ctx.resolver_last_sent = calloc(server_address_count, sizeof(*client_ctx.resolver_last_sent));
    client_ctx.resolver_last_lost = calloc(server_address_count, sizeof(*client_ctx.resolver_last_lost));
    client_ctx.resolver_loss_permille = calloc(server_address_count, sizeof(*client_ctx.resolver_loss_permille));
    client_ctx.resolver_cwin = calloc(server_address_count, sizeof(*client_ctx.resolver_cwin));
    client_ctx.resolver_sampled_at = calloc(server_address_count, sizeof(*client_ctx.resolver_sampled_at));
    client_ctx.resolver_unhealthy_until = calloc(server_address_count, sizeof(*client_ctx.resolver_unhealthy_until));
    client_ctx.resolver_quality_log_next_at = calloc(server_address_count, sizeof(*client_ctx.resolver_quality_log_next_at));
    client_ctx.resolver_send_mtu = calloc(server_address_count, sizeof(*client_ctx.resolver_send_mtu));
    client_ctx.resolver_mtu_adjusted_at = calloc(server_address_count, sizeof(*client_ctx.resolver_mtu_adjusted_at));
    client_ctx.resolver_mtu_good_windows = calloc(server_address_count, sizeof(*client_ctx.resolver_mtu_good_windows));
    client_ctx.resolver_rtt_ready = calloc(server_address_count, sizeof(*client_ctx.resolver_rtt_ready));
    if (client_ctx.resolver_probe_next_at == NULL || client_ctx.resolver_probe_delay == NULL ||
        client_ctx.resolver_path_ids == NULL || client_ctx.resolver_rtt_us == NULL ||
        client_ctx.resolver_sent == NULL || client_ctx.resolver_lost == NULL ||
        client_ctx.resolver_last_sent == NULL || client_ctx.resolver_last_lost == NULL ||
        client_ctx.resolver_loss_permille == NULL || client_ctx.resolver_cwin == NULL ||
        client_ctx.resolver_sampled_at == NULL ||
        client_ctx.resolver_unhealthy_until == NULL || client_ctx.resolver_quality_log_next_at == NULL ||
        client_ctx.resolver_send_mtu == NULL || client_ctx.resolver_mtu_adjusted_at == NULL ||
        client_ctx.resolver_mtu_good_windows == NULL || client_ctx.resolver_rtt_ready == NULL) {
        fprintf(stderr, "Could not allocate resolver probe state\n");
        free(client_ctx.resolver_probe_next_at);
        free(client_ctx.resolver_probe_delay);
        free(client_ctx.resolver_path_ids);
        free(client_ctx.resolver_rtt_us);
        free(client_ctx.resolver_sent);
        free(client_ctx.resolver_lost);
        free(client_ctx.resolver_last_sent);
        free(client_ctx.resolver_last_lost);
        free(client_ctx.resolver_loss_permille);
        free(client_ctx.resolver_cwin);
        free(client_ctx.resolver_sampled_at);
        free(client_ctx.resolver_unhealthy_until);
        free(client_ctx.resolver_quality_log_next_at);
        free(client_ctx.resolver_send_mtu);
        free(client_ctx.resolver_mtu_adjusted_at);
        free(client_ctx.resolver_mtu_good_windows);
        free(client_ctx.resolver_rtt_ready);
        picoquic_free(quic);
        return -1;
    }
    for (size_t i = 0; i < server_address_count; i++) {
        client_ctx.resolver_send_mtu[i] = client_query_payload_budget;
    }
    slipstream_client_reset_paths(&client_ctx);

    ret = slipstream_client_connect_next_resolver(quic, &client_ctx);
    if (ret != 0) {
        fprintf(stderr, "Could not connect to server, will retry\n");
        client_ctx.reconnect_pending = true;
        client_ctx.reconnect_at = picoquic_current_time();
        ret = 0;
    }

    // Create listening socket
    client_ctx.listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_ctx.listen_sock < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(client_ctx.listen_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in listen_addr = {0};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(client_ctx.listen_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind() failed");
        close(client_ctx.listen_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(client_ctx.listen_sock, 5) < 0) {
        perror("listen() failed");
        close(client_ctx.listen_sock);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Client listening on tcp 0.0.0.0:%d\n", listen_port);

    picoquic_packet_loop_param_t param = {0};
    param.local_af = client_ctx.server_addresses[0].server_address.ss_family;

    // For loopback testing, we need to disable hardware GSO since packets on loopback never reach a hardware NIC
    // $ ethtool -K lo tx-udp-segmentation off
    // And ensure that gso is on
    // $ ethtool -k lo | grep generic-segmentation-offload
    // generic-segmentation-offload: on
    param.do_not_use_gso = !gso;

    param.is_client = 1;
    param.decode = client_decode;
    param.encode = client_encode;
    param.delay_max = 1000000;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.quic = quic;
    thread_ctx.param = &param;
    thread_ctx.loop_callback = slipstream_client_sockloop_callback;
    thread_ctx.loop_callback_ctx = &client_ctx;

    /* Open the wake up pipe or event */
    picoquic_open_network_wake_up(&thread_ctx, &ret);

    client_ctx.thread_ctx = &thread_ctx;

    slipstream_client_accepter_args* args = malloc(sizeof(slipstream_client_accepter_args));
    args->fd = client_ctx.listen_sock;
    args->client_ctx = &client_ctx;
    args->thread_ctx = &thread_ctx;

    pthread_t thread;
    if (pthread_create(&thread, NULL, slipstream_client_accepter, args) != 0) {
        perror("pthread_create() failed for thread");
        free(args);
    }

    signal(SIGTERM, client_sighandler);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
    // picoquic_packet_loop_v3(&thread_ctx);
    slipstream_packet_loop(&thread_ctx);
    ret = thread_ctx.return_code;

    /* And finish. */
    fprintf(stderr, "Client exit, ret = %d\n", ret);

    free(client_ctx.resolver_probe_next_at);
    free(client_ctx.resolver_probe_delay);
    free(client_ctx.resolver_path_ids);
    free(client_ctx.resolver_rtt_us);
    free(client_ctx.resolver_sent);
    free(client_ctx.resolver_lost);
    free(client_ctx.resolver_last_sent);
    free(client_ctx.resolver_last_lost);
    free(client_ctx.resolver_loss_permille);
    free(client_ctx.resolver_cwin);
    free(client_ctx.resolver_sampled_at);
    free(client_ctx.resolver_unhealthy_until);
    free(client_ctx.resolver_quality_log_next_at);
    free(client_ctx.resolver_send_mtu);
    free(client_ctx.resolver_mtu_adjusted_at);
    free(client_ctx.resolver_mtu_good_windows);
    free(client_ctx.resolver_rtt_ready);
    picoquic_free(quic);

    return ret;
}
