/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_FULL_CONN_H
#define LSQUIC_FULL_CONN_H

struct lsquic_conn;
struct lsquic_stream_if;
struct lsquic_engine_public;

struct lsquic_conn *
lsquic_gquic_full_conn_client_new (struct lsquic_engine_public *,
               const struct lsquic_stream_if *,
               void *stream_if_ctx,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
           const char *hostname, unsigned short max_packet_size, int is_ipv4);

struct lsquic_conn *
lsquic_ietf_full_conn_client_new (struct lsquic_engine_public *,
               const struct lsquic_stream_if *,
               void *stream_if_ctx,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
           const char *hostname, unsigned short max_packet_size, int is_ipv4,
           const unsigned char *token, size_t);

struct dcid_elem
{
    /* de_hash_el and de_next could be made into a union if we go over
     * 128 bytes.
     */
    struct lsquic_hash_elem     de_hash_el;
    TAILQ_ENTRY(dcid_elem)      de_next;
    lsquic_cid_t                de_cid;
    unsigned                    de_seqno;
    enum {
        DE_SRST     = 1 << 0, /* de_srst is set */
    }                           de_flags;
    unsigned char               de_srst[IQUIC_SRESET_TOKEN_SZ];
};

#endif
