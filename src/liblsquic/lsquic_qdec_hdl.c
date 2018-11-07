/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_qdec_hdl.c -- QPACK decoder streams handler
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sfcw.h"
#include "lsquic_hq.h"
#include "lsquic_varint.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_frab_list.h"
#include "lsqpack.h"
#include "lsquic_hq.h"
#include "lsquic_http1x_if.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_headers.h"
#include "lsquic_http1x_if.h"

#define LSQUIC_LOGGER_MODULE LSQLM_QDEC_HDL
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(qdh->qdh_conn)
#include "lsquic_logger.h"

static void
qdh_hblock_unblocked (void *);


static void
qdh_begin_out (struct qpack_dec_hdl *qdh)
{
    if (0 == lsquic_frab_list_write(&qdh->qdh_fral,
                                (unsigned char []) { HQUST_QPACK_DEC }, 1))
        lsquic_stream_wantwrite(qdh->qdh_dec_sm_out, 1);
    else
    {
        LSQ_WARN("could not write to frab list");
        /* TODO: abort connection */
    }
}


static void
qdh_write_decoder (void *stream, void *buf, size_t sz)
{
    struct qpack_dec_hdl *const qdh = stream;
    ssize_t nw;
    int want_already;

    if (!qdh->qdh_dec_sm_out)   /* XXX Make this impossible */
    {
        LSQ_WARN("outgoing QPACK decoder stream does not exist");
        return;
    }

    nw = lsquic_stream_write(qdh->qdh_dec_sm_out, buf, sz);
    if (nw < 0)
    {
        LSQ_INFO("error writing to outgoing QPACK decoder stream: %s",
                                                        strerror(errno));
        /* TODO: abort connection */
        return;
    }
    LSQ_DEBUG("wrote %zd bytes to outgoing QPACK decoder stream", nw);

    if ((size_t) nw < sz)
    {
        want_already = !lsquic_frab_list_empty(&qdh->qdh_fral);
        if (0 == lsquic_frab_list_write(&qdh->qdh_fral,
                        (unsigned char *) buf + nw, sz - (size_t) nw))
        {
            LSQ_DEBUG("wrote %zu overflow bytes to frab list",
                                                    sz - (size_t) nw);
            if (!want_already)
                lsquic_stream_wantwrite(qdh->qdh_dec_sm_out, 1);
        }
        else
        {
            LSQ_INFO("error writing to frab list");
            /* TODO: abort connection */
        }
    }
}


int
lsquic_qdh_init (struct qpack_dec_hdl *qdh, const struct lsquic_conn *conn,
                    int is_server, const struct lsquic_engine_public *enpub,
                    unsigned dyn_table_size, unsigned max_risked_streams)
{
    qdh->qdh_conn = conn;
    lsquic_frab_list_init(&qdh->qdh_fral, 0x400, NULL, NULL, NULL);
    lsqpack_dec_init(&qdh->qdh_decoder, dyn_table_size,
                        max_risked_streams, qdh_write_decoder, qdh,
                        qdh_hblock_unblocked);
    qdh->qdh_flags |= QDH_INITIALIZED;
    qdh->qdh_enpub = enpub;
    if (qdh->qdh_enpub->enp_hsi_if == lsquic_http1x_if)
    {
        qdh->qdh_h1x_ctor_ctx = (struct http1x_ctor_ctx) {
            .conn           = conn,
            .max_headers_sz = 0x10000,  /* XXX */
            .is_server      = is_server,
        };
        qdh->qdh_hsi_ctx = &qdh->qdh_h1x_ctor_ctx;
    }
    else
        qdh->qdh_hsi_ctx = qdh->qdh_enpub->enp_hsi_ctx;
    if (qdh->qdh_dec_sm_out)
        qdh_begin_out(qdh);
    if (qdh->qdh_enc_sm_in)
        lsquic_stream_wantread(qdh->qdh_enc_sm_in, 1);
    LSQ_DEBUG("initialized");
    return 0;
}


void
lsquic_qdh_cleanup (struct qpack_dec_hdl *qdh)
{
    if (qdh->qdh_flags & QDH_INITIALIZED)
    {
        LSQ_DEBUG("cleanup");
        lsqpack_dec_cleanup(&qdh->qdh_decoder);
        lsquic_frab_list_cleanup(&qdh->qdh_fral);
        qdh->qdh_flags &= ~QDH_INITIALIZED;
    }
}

static lsquic_stream_ctx_t *
qdh_out_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct qpack_dec_hdl *const qdh = stream_if_ctx;
    qdh->qdh_dec_sm_out = stream;
    if (qdh->qdh_flags & QDH_INITIALIZED)
        qdh_begin_out(qdh);
    LSQ_DEBUG("initialized outgoing decoder stream");
    return (void *) qdh;
}


static void
qdh_out_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    struct lsquic_reader reader = {
        .lsqr_read  = lsquic_frab_list_read,
        .lsqr_size  = lsquic_frab_list_size,
        .lsqr_ctx   = &qdh->qdh_fral,
    };
    ssize_t nw;

    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
    {
        LSQ_DEBUG("wrote %zd bytes to stream", nw);
        (void) lsquic_stream_flush(stream);
        if (lsquic_frab_list_empty(&qdh->qdh_fral))
            lsquic_stream_wantwrite(stream, 0);
    }
    else
    {
        /* TODO: abort connection */
        LSQ_WARN("cannot write to stream: %s", strerror(errno));
        lsquic_stream_wantwrite(stream, 0);
    }
}


static void
qdh_out_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    qdh->qdh_dec_sm_out = NULL;
    LSQ_DEBUG("closed outgoing decoder stream");
}


static void
qdh_out_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static const struct lsquic_stream_if qdh_dec_sm_out_if =
{
    .on_new_stream  = qdh_out_on_new,
    .on_read        = qdh_out_on_read,
    .on_write       = qdh_out_on_write,
    .on_close       = qdh_out_on_close,
};
const struct lsquic_stream_if *const lsquic_qdh_dec_sm_out_if =
                                                    &qdh_dec_sm_out_if;


static lsquic_stream_ctx_t *
qdh_in_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct qpack_dec_hdl *const qdh = stream_if_ctx;
    qdh->qdh_enc_sm_in = stream;
    if (qdh->qdh_flags & QDH_INITIALIZED)
        lsquic_stream_wantread(qdh->qdh_enc_sm_in, 1);
    LSQ_DEBUG("initialized incoming encoder stream");
    return (void *) qdh;
}


static size_t
qdh_read_decoder_stream (void *ctx, const unsigned char *buf, size_t sz,
                                                                    int fin)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    int s;

    if (fin)
    {
        LSQ_INFO("decoder stream is closed");
        /* TODO: abort connection */
        goto end;
    }

    s = lsqpack_dec_enc_in(&qdh->qdh_decoder, buf, sz);
    if (s != 0)
    {
        LSQ_INFO("error reading decoder stream");
        /* TODO: abort connection */
        goto end;
    }
    LSQ_DEBUG("successfully fed %zu bytes to QPACK decoder", sz);

  end:
    return sz;
}


static void
qdh_in_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    ssize_t nread;

    nread = lsquic_stream_readf(stream, qdh_read_decoder_stream, qdh);
    if (nread < 0)
    {
        LSQ_WARN("cannot read from decoder stream");
        lsquic_stream_wantread(stream, 0);
        /* TODO: abort connection */
    }
}


static void
qdh_in_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    qdh->qdh_enc_sm_in = NULL;
    LSQ_DEBUG("closed incoming decoder stream");
}


static void
qdh_in_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static const struct lsquic_stream_if qdh_enc_sm_in_if =
{
    .on_new_stream  = qdh_in_on_new,
    .on_read        = qdh_in_on_read,
    .on_write       = qdh_in_on_write,
    .on_close       = qdh_in_on_close,
};
const struct lsquic_stream_if *const lsquic_qdh_enc_sm_in_if =
                                                    &qdh_enc_sm_in_if;


static void
qdh_hblock_unblocked (void *stream_p)
{
    struct lsquic_stream *const stream = stream_p;
    struct qpack_dec_hdl *const qdh = lsquic_stream_get_qdh(stream);

    LSQ_DEBUG("header block for stream %"PRIu64" unblocked", stream->id);
    (void) lsquic_stream_wantread(stream, 1);
}


static int
qdh_supply_hset_to_stream (struct qpack_dec_hdl *qdh,
            struct lsquic_stream *stream, struct lsqpack_header_set *qset)
{
    const struct lsquic_hset_if *const hset_if = qdh->qdh_enpub->enp_hsi_if;
    struct uncompressed_headers *uh = NULL;
    const struct lsqpack_header *header;
    enum lsquic_header_status st;
    unsigned i;
    void *hset;

    hset = hset_if->hsi_create_header_set(qdh->qdh_hsi_ctx, 0);
    if (!hset)
    {
        LSQ_INFO("call to hsi_create_header_set failed");
        return -1;
    }

    LSQ_DEBUG("got header set for stream %"PRIu64, stream->id);

    for (i = 0; i < qset->qhs_count; ++i)
    {
        header = qset->qhs_headers[i];
        LSQ_DEBUG("%.*s: %.*s", header->qh_name_len, header->qh_name,
                                        header->qh_value_len, header->qh_value);
        st = hset_if->hsi_process_header(hset,
                    header->qh_flags & QH_ID_SET ? 62 /* XXX: 62 */ + header->qh_static_id : 0,
                    header->qh_name, header->qh_name_len,
                    header->qh_value, header->qh_value_len);
        if (st != LSQUIC_HDR_OK)
            goto err;
    }

    lsqpack_dec_destroy_header_set(qset);
    st = hset_if->hsi_process_header(hset, 0, 0, 0, 0, 0);
    if (st != LSQUIC_HDR_OK)
        goto err;

    uh = calloc(1, sizeof(*uh));
    if (!uh)
        goto err;
    uh->uh_stream_id = stream->id;
    uh->uh_oth_stream_id = 0;
    uh->uh_weight = 0;
    uh->uh_exclusive = -1;
    /* TODO: determine FIN
    if (fr->fr_state.header.hfh_flags & HFHF_END_STREAM)
        uh->uh_flags    |= UH_FIN;
        */
    if (hset_if == lsquic_http1x_if)
        uh->uh_flags    |= UH_H1H;
    uh->uh_hset = hset;
    if (0 != lsquic_stream_uh_in(stream, uh))
        goto err;
    LSQ_DEBUG("converted qset to hset and gave it to stream %"PRIu64,
                                                                stream->id);
    return 0;

  err:
    lsqpack_dec_destroy_header_set(qset);
    hset_if->hsi_discard_header_set(hset);
    free(uh);
    return -1;
}


static enum lsqpack_read_header_status
qdh_header_read_results (struct qpack_dec_hdl *qdh,
        struct lsquic_stream *stream, enum lsqpack_read_header_status rhs,
        struct lsqpack_header_set *qset)
{
    if (rhs == LQRHS_DONE)
    {
        if (qset)
        {
            if (0 != qdh_supply_hset_to_stream(qdh, stream, qset))
                return LQRHS_ERROR;
        }
        else
        {
            assert(0);  /* XXX TODO What do we do here? */
            return LQRHS_ERROR;
        }
    }
    return rhs;
}


enum lsqpack_read_header_status
lsquic_qdh_header_in_begin (struct qpack_dec_hdl *qdh,
                        struct lsquic_stream *stream, uint64_t header_size,
                        const unsigned char **buf, size_t bufsz)
{
    enum lsqpack_read_header_status rhs;
    struct lsqpack_header_set *qset;

    if (qdh->qdh_flags & QDH_INITIALIZED)
    {
        rhs = lsqpack_dec_header_in(&qdh->qdh_decoder, stream, stream->id,
                                            header_size, buf, bufsz, &qset);
        return qdh_header_read_results(qdh, stream, rhs, qset);
    }
    else
    {
        LSQ_WARN("not initialized: cannot process header block");
        return LQRHS_ERROR;
    }

}


enum lsqpack_read_header_status
lsquic_qdh_header_in_continue (struct qpack_dec_hdl *qdh,
        struct lsquic_stream *stream, const unsigned char **buf, size_t bufsz)
{
    enum lsqpack_read_header_status rhs;
    struct lsqpack_header_set *qset;

    if (qdh->qdh_flags & QDH_INITIALIZED)
    {
        rhs = lsqpack_dec_header_read(&qdh->qdh_decoder, stream,
                                                            buf, bufsz, &qset);
        return qdh_header_read_results(qdh, stream, rhs, qset);
    }
    else
    {
        LSQ_WARN("not initialized: cannot process header block");
        return LQRHS_ERROR;
    }
}


void
lsquic_qdh_unref_stream (struct qpack_dec_hdl *qdh,
                                                struct lsquic_stream *stream)
{
    LSQ_WARN("%s: TODO", __func__);
}
