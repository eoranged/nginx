
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
static u_char *ngx_http_api_prometheus_server_zones(ngx_http_request_t *r,
    u_char *p);
static u_char *ngx_http_api_prometheus_slabs(u_char *p);


ngx_int_t
ngx_http_api_prometheus(ngx_http_request_t *r)
{
    ngx_buf_t  *b;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    b = ngx_http_api_prometheus_create_buffer(r);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, "nginxplus_up 1" CRLF,
                         sizeof("nginxplus_up 1" CRLF) - 1);

    b->last = ngx_http_api_prometheus_server_zones(r, b->last);
    b->last = ngx_http_api_prometheus_caches(b->last);
    b->last = ngx_http_api_prometheus_upstreams(b->last);
    b->last = ngx_http_api_prometheus_slabs(b->last);

    return ngx_http_api_send_prometheus(r, b);
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


static u_char *
ngx_http_api_prometheus_server_zones(ngx_http_request_t *r, u_char *p)
{
    ngx_uint_t                  i;
    ngx_shm_zone_t            **zone;
    ngx_http_api_zone_ctx_t    *ctx;
    ngx_http_api_zone_shctx_t  *sh;
    ngx_http_api_main_conf_t   *amcf;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_api_module);
    if (amcf == NULL || amcf->zones == NULL) {
        return p;
    }

    zone = amcf->zones->elts;

    for (i = 0; i < amcf->zones->nelts; i++) {
        ctx = zone[i]->data;
        if (ctx == NULL || ctx->sh == NULL) {
            continue;
        }

        sh = ctx->sh;

        p = ngx_sprintf(p, "nginxplus_server_zone_processing"
                        "{server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->processing);
        p = ngx_sprintf(p, "nginxplus_server_zone_requests"
                        "{server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->requests);
        p = ngx_sprintf(p, "nginxplus_server_zone_responses"
                        "{code=\"1xx\",server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->responses[0]);
        p = ngx_sprintf(p, "nginxplus_server_zone_responses"
                        "{code=\"2xx\",server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->responses[1]);
        p = ngx_sprintf(p, "nginxplus_server_zone_responses"
                        "{code=\"3xx\",server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->responses[2]);
        p = ngx_sprintf(p, "nginxplus_server_zone_responses"
                        "{code=\"4xx\",server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->responses[3]);
        p = ngx_sprintf(p, "nginxplus_server_zone_responses"
                        "{code=\"5xx\",server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->responses[4]);
        p = ngx_sprintf(p, "nginxplus_server_zone_discarded"
                        "{server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->discarded);
        p = ngx_sprintf(p, "nginxplus_server_zone_received"
                        "{server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->received);
        p = ngx_sprintf(p, "nginxplus_server_zone_sent"
                        "{server_zone=\"%V\"} %uA" CRLF,
                        &ctx->name, sh->sent);
    }

    return p;
}


static u_char *
ngx_http_api_prometheus_slabs(u_char *p)
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

            p = ngx_sprintf(p, "nginxplus_slab_pages_used"
                            "{slab=\"%V\"} %ui" CRLF,
                            &shm_zone[i].shm.name,
                            (ngx_uint_t) (shpool->last - shpool->pages
                                          - shpool->pfree));
            p = ngx_sprintf(p, "nginxplus_slab_pages_free"
                            "{slab=\"%V\"} %ui" CRLF,
                            &shm_zone[i].shm.name, shpool->pfree);

            for (j = 0, size = shpool->min_size;
                 size <= ngx_pagesize / 2;
                 j++, size <<= 1)
            {
                p = ngx_sprintf(p, "nginxplus_slab_slot_used"
                                "{slab=\"%V\",slot=\"%uz\"} %ui" CRLF,
                                &shm_zone[i].shm.name, size,
                                shpool->stats[j].used);
                p = ngx_sprintf(p, "nginxplus_slab_slot_free"
                                "{slab=\"%V\",slot=\"%uz\"} %ui" CRLF,
                                &shm_zone[i].shm.name, size,
                                shpool->stats[j].total
                                - shpool->stats[j].used);
                p = ngx_sprintf(p, "nginxplus_slab_slot_reqs"
                                "{slab=\"%V\",slot=\"%uz\"} %ui" CRLF,
                                &shm_zone[i].shm.name, size,
                                shpool->stats[j].reqs);
                p = ngx_sprintf(p, "nginxplus_slab_slot_fails"
                                "{slab=\"%V\",slot=\"%uz\"} %ui" CRLF,
                                &shm_zone[i].shm.name, size,
                                shpool->stats[j].fails);
            }
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        shm_zone = part->elts;
    }

    return p;
}
