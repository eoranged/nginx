
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_upstream_round_robin.h>

#if (NGX_STREAM_UPSTREAM_ZONE)
#include <ngx_stream.h>
#include <ngx_stream_upstream_round_robin.h>
#endif

#include "ngx_http_api_module.h"


static ngx_buf_t *ngx_http_api_prometheus_create_buffer(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_prometheus_reserve(
    ngx_http_api_prometheus_ctx_t *ctx, size_t size);
static ngx_int_t ngx_http_api_prometheus_server_zones(
    ngx_http_api_prometheus_ctx_t *ctx);
static ngx_int_t ngx_http_api_prometheus_resolvers(
    ngx_http_api_prometheus_ctx_t *ctx);
static ngx_int_t ngx_http_api_prometheus_resolver(
    ngx_http_api_prometheus_ctx_t *ctx, ngx_resolver_t *resolver);
static ngx_int_t ngx_http_api_prometheus_slabs(
    ngx_http_api_prometheus_ctx_t *ctx);


ngx_int_t
ngx_http_api_prometheus(ngx_http_request_t *r)
{
    ngx_buf_t                    *b;
    ngx_http_api_prometheus_ctx_t ctx;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    b = ngx_http_api_prometheus_create_buffer(r);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx.request = r;
    ctx.buf = b;

    if (ngx_http_api_prometheus_append(&ctx, "nginxplus_up 1" CRLF)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_api_prometheus_server_zones(&ctx) != NGX_OK
        || ngx_http_api_prometheus_caches(&ctx) != NGX_OK
        || ngx_http_api_prometheus_upstreams(&ctx) != NGX_OK
        || ngx_http_api_prometheus_resolvers(&ctx) != NGX_OK
        || ngx_http_api_prometheus_slabs(&ctx) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_api_send_prometheus(r, ctx.buf);
}


ngx_int_t
ngx_http_api_prometheus_append(ngx_http_api_prometheus_ctx_t *ctx,
    const char *fmt, ...)
{
    u_char   *p;
    va_list   args;

    if (ngx_http_api_prometheus_reserve(ctx, 4096) != NGX_OK) {
        return NGX_ERROR;
    }

    va_start(args, fmt);
    p = ngx_vslprintf(ctx->buf->last, ctx->buf->end, fmt, args);
    va_end(args);

    if (p == ctx->buf->end) {
        return NGX_ERROR;
    }

    ctx->buf->last = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_prometheus_reserve(ngx_http_api_prometheus_ctx_t *ctx, size_t size)
{
    size_t      used, old_size, new_size;
    ngx_buf_t  *b;

    if ((size_t) (ctx->buf->end - ctx->buf->last) >= size) {
        return NGX_OK;
    }

    used = ctx->buf->last - ctx->buf->pos;
    old_size = ctx->buf->end - ctx->buf->pos;
    new_size = old_size * 2;

    while (new_size - used < size) {
        new_size *= 2;
    }

    b = ngx_create_temp_buf(ctx->request->pool, new_size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last, ctx->buf->pos, used);
    ctx->buf = b;

    return NGX_OK;
}


static ngx_buf_t *
ngx_http_api_prometheus_create_buffer(ngx_http_request_t *r)
{
    size_t                           size;
    ngx_uint_t                       i;
    ngx_list_part_t                 *part;
    ngx_shm_zone_t                  *shm_zone;
    ngx_http_api_main_conf_t        *amcf;
    ngx_http_upstream_rr_peers_t    *peers;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_http_upstream_main_conf_t   *umcf;

    size = 16384;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_api_module);
    if (amcf && amcf->zones) {
        size += amcf->zones->nelts * 2048;
    }

#if (NGX_HTTP_CACHE)
    if (ngx_http_file_caches) {
        size += ngx_http_file_caches->nelts * 4096;
    }
#endif

    part = (ngx_list_part_t *) &((ngx_cycle_t *) ngx_cycle)->shared_memory.part;
    shm_zone = part->elts;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            size += shm_zone[i].shm.name.len * 16 + 8192;
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        shm_zone = part->elts;
    }

    umcf = ngx_http_cycle_get_module_main_conf(((ngx_cycle_t *) ngx_cycle),
                                               ngx_http_upstream_module);
    if (umcf) {
        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            peers = uscfp[i]->peer.data;
            if (peers == NULL) {
                continue;
            }

            size += (peers->number + (peers->next ? peers->next->number : 0))
                    * (1024 + uscfp[i]->host.len * 4);
        }
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
    {
        ngx_stream_upstream_rr_peers_t    *speers;
        ngx_stream_upstream_srv_conf_t   **suscfp;
        ngx_stream_upstream_main_conf_t   *sumcf;

        sumcf = ngx_stream_cycle_get_module_main_conf(
                                            ((ngx_cycle_t *) ngx_cycle),
                                            ngx_stream_upstream_module);
        if (sumcf) {
            suscfp = sumcf->upstreams.elts;

            for (i = 0; i < sumcf->upstreams.nelts; i++) {
                speers = suscfp[i]->peer.data;
                if (speers == NULL) {
                    continue;
                }

                size += (speers->number
                         + (speers->next ? speers->next->number : 0))
                        * (1024 + suscfp[i]->host.len * 4);
            }
        }
    }
#endif

    return ngx_create_temp_buf(r->pool, size);
}


static ngx_int_t
ngx_http_api_prometheus_server_zones(ngx_http_api_prometheus_ctx_t *pmctx)
{
    ngx_uint_t                  i;
    ngx_shm_zone_t            **zone;
    ngx_http_api_zone_ctx_t    *zctx;
    ngx_http_api_zone_shctx_t  *sh;
    ngx_http_api_main_conf_t   *amcf;

    amcf = ngx_http_get_module_main_conf(pmctx->request, ngx_http_api_module);
    if (amcf == NULL || amcf->zones == NULL) {
        return NGX_OK;
    }

    zone = amcf->zones->elts;

    for (i = 0; i < amcf->zones->nelts; i++) {
        zctx = zone[i]->data;
        if (zctx == NULL || zctx->sh == NULL) {
            continue;
        }

        sh = zctx->sh;

        if (ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_processing"
            "{server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->processing) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_requests"
            "{server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->requests) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_responses"
            "{code=\"1xx\",server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->responses[0]) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_responses"
            "{code=\"2xx\",server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->responses[1]) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_responses"
            "{code=\"3xx\",server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->responses[2]) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_responses"
            "{code=\"4xx\",server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->responses[3]) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_responses"
            "{code=\"5xx\",server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->responses[4]) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_discarded"
            "{server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->discarded) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_received"
            "{server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->received) != NGX_OK
            || ngx_http_api_prometheus_append(pmctx,
            "nginxplus_server_zone_sent"
            "{server_zone=\"%V\"} %uA" CRLF,
            &zctx->name, sh->sent) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_prometheus_resolvers(ngx_http_api_prometheus_ctx_t *ctx)
{
    ngx_uint_t                       i;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_http_upstream_main_conf_t   *umcf;

    umcf = ngx_http_cycle_get_module_main_conf((ngx_cycle_t *) ngx_cycle,
                                               ngx_http_upstream_module);
    if (umcf) {
        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            if (ngx_http_api_prometheus_resolver(ctx, uscfp[i]->resolver)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
    {
        ngx_stream_upstream_srv_conf_t   **suscfp;
        ngx_stream_upstream_main_conf_t   *sumcf;

        sumcf = ngx_stream_cycle_get_module_main_conf(
                                            (ngx_cycle_t *) ngx_cycle,
                                            ngx_stream_upstream_module);
        if (sumcf) {
            suscfp = sumcf->upstreams.elts;

            for (i = 0; i < sumcf->upstreams.nelts; i++) {
                if (ngx_http_api_prometheus_resolver(ctx, suscfp[i]->resolver)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }
        }
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_prometheus_resolver(ngx_http_api_prometheus_ctx_t *ctx,
    ngx_resolver_t *resolver)
{
    ngx_resolver_status_zone_t  *status;

    if (resolver == NULL || resolver->status_zone.len == 0) {
        return NGX_OK;
    }

    status = resolver->status_zone_shm ? resolver->status_zone_shm->data : NULL;

    if (ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_name"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->name : resolver->name) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_srv"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->srv : resolver->srv) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_addr"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->addr : resolver->addr) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_noerror"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->noerror : resolver->noerror) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_formerr"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->formerr : resolver->formerr) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_servfail"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->servfail : resolver->servfail) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_nxdomain"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->nxdomain : resolver->nxdomain) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_notimp"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->notimp : resolver->notimp) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_refused"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->refused : resolver->refused) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_timedout"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->timedout : resolver->timedout) != NGX_OK
        || ngx_http_api_prometheus_append(ctx, "nginxplus_resolver_unknown"
        "{resolver=\"%V\"} %uA" CRLF, &resolver->status_zone,
        status ? status->unknown : resolver->unknown) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_prometheus_slabs(ngx_http_api_prometheus_ctx_t *ctx)
{
    size_t            size;
    ngx_uint_t        i, j;
    ngx_list_part_t  *part;
    ngx_shm_zone_t   *shm_zone;
    ngx_slab_pool_t  *shpool;

    part = (ngx_list_part_t *) &((ngx_cycle_t *) ngx_cycle)->shared_memory.part;
    shm_zone = part->elts;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            if (shm_zone[i].shm.addr == NULL) {
                continue;
            }

            shpool = (ngx_slab_pool_t *) shm_zone[i].shm.addr;

            if (ngx_http_api_prometheus_append(ctx,
                "nginxplus_slab_pages_used"
                "{slab=\"%V\"} %ui" CRLF, &shm_zone[i].shm.name,
                (ngx_uint_t) (shpool->last - shpool->pages - shpool->pfree))
                != NGX_OK
                || ngx_http_api_prometheus_append(ctx,
                "nginxplus_slab_pages_free"
                "{slab=\"%V\"} %ui" CRLF, &shm_zone[i].shm.name,
                shpool->pfree) != NGX_OK)
            {
                return NGX_ERROR;
            }

            for (j = 0, size = shpool->min_size;
                 size <= ngx_pagesize / 2;
                 j++, size <<= 1)
            {
                if (ngx_http_api_prometheus_append(ctx,
                    "nginxplus_slab_slot_used"
                    "{slab=\"%V\",slot=\"%uz\"} %ui" CRLF,
                    &shm_zone[i].shm.name, size, shpool->stats[j].used)
                    != NGX_OK
                    || ngx_http_api_prometheus_append(ctx,
                    "nginxplus_slab_slot_free"
                    "{slab=\"%V\",slot=\"%uz\"} %ui" CRLF,
                    &shm_zone[i].shm.name, size,
                    shpool->stats[j].total - shpool->stats[j].used)
                    != NGX_OK
                    || ngx_http_api_prometheus_append(ctx,
                    "nginxplus_slab_slot_reqs"
                    "{slab=\"%V\",slot=\"%uz\"} %ui" CRLF,
                    &shm_zone[i].shm.name, size, shpool->stats[j].reqs)
                    != NGX_OK
                    || ngx_http_api_prometheus_append(ctx,
                    "nginxplus_slab_slot_fails"
                    "{slab=\"%V\",slot=\"%uz\"} %ui" CRLF,
                    &shm_zone[i].shm.name, size, shpool->stats[j].fails)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        shm_zone = part->elts;
    }

    return NGX_OK;
}
