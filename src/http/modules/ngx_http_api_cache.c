
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_api_module.h"


#if (NGX_HTTP_CACHE)

static ngx_int_t ngx_http_api_cache_list(ngx_http_request_t *r,
    ngx_http_file_cache_t *cache);
static ngx_http_file_cache_t *ngx_http_api_cache_find(ngx_str_t *name);
static u_char *ngx_http_api_cache_write(u_char *p, ngx_http_file_cache_t *cache,
    ngx_uint_t name);
static u_char *ngx_http_api_cache_write_group(u_char *p, const char *name,
    ngx_atomic_uint_t responses, ngx_uint_t written);
static void ngx_http_api_cache_reset(ngx_http_file_cache_t *cache);

#endif


ngx_int_t
ngx_http_api_caches(ngx_http_request_t *r)
{
#if (NGX_HTTP_CACHE)
    u_char                 *p, *last;
    ngx_str_t               name;
    ngx_http_file_cache_t  *cache;

    if (r->uri.len < sizeof("/api/9/http/caches") - 1
        || ngx_strncmp(r->uri.data, "/api/9/http/caches",
                       sizeof("/api/9/http/caches") - 1)
           != 0)
    {
        return NGX_DECLINED;
    }

    p = r->uri.data + sizeof("/api/9/http/caches") - 1;
    last = r->uri.data + r->uri.len;

    if (p == last || (last - p == 1 && *p == '/')) {
        if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
            return ngx_http_api_cache_list(r, NULL);
        }

        return NGX_HTTP_NOT_ALLOWED;
    }

    if (*p++ != '/') {
        return NGX_HTTP_NOT_FOUND;
    }

    name.data = p;
    name.len = last - p;

    if (name.len == 0 || ngx_strlchr(p, last, '/') != NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    cache = ngx_http_api_cache_find(&name);
    if (cache == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
        return ngx_http_api_cache_list(r, cache);
    }

    if (r->method == NGX_HTTP_DELETE) {
        ngx_http_api_cache_reset(cache);
        return ngx_http_api_send_no_content(r);
    }

    return NGX_HTTP_NOT_ALLOWED;
#else
    return NGX_DECLINED;
#endif
}


void
ngx_http_api_cache_log(ngx_http_request_t *r)
{
#if (NGX_HTTP_CACHE)
    ngx_uint_t                  status;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_upstream_t        *u;
    ngx_http_file_cache_t      *cache;

    if (r != r->main) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (!clcf->log_subrequest) {
            return;
        }
    }

    u = r->upstream;

    if (u == NULL || u->cache_status == 0 || r->cache == NULL) {
        return;
    }

    status = u->cache_status;
    if (status == NGX_HTTP_CACHE_SCARCE
        || status > NGX_HTTP_CACHE_STATUS_COUNT)
    {
        return;
    }

    cache = r->cache->file_cache;
    if (cache == NULL || cache->sh == NULL) {
        return;
    }

    (void) ngx_atomic_fetch_add(&cache->sh->stats.responses[status - 1], 1);
#endif
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_api_cache_list(ngx_http_request_t *r, ngx_http_file_cache_t *cache)
{
    ngx_buf_t               *b;
    ngx_uint_t               i;
    ngx_http_file_cache_t  **caches;

    b = ngx_http_api_create_buffer(r);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (cache) {
        b->last = ngx_http_api_cache_write(b->last, cache, 0);
        b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

        return ngx_http_api_send(r, b);
    }

    *b->last++ = '{';

    if (ngx_http_file_caches) {
        caches = ngx_http_file_caches->elts;

        for (i = 0; i < ngx_http_file_caches->nelts; i++) {
            if (i != 0) {
                *b->last++ = ',';
            }

            b->last = ngx_http_api_cache_write(b->last, caches[i], 1);
        }
    }

    b->last = ngx_cpymem(b->last, "}" CRLF, sizeof("}" CRLF) - 1);

    return ngx_http_api_send(r, b);
}


static ngx_http_file_cache_t *
ngx_http_api_cache_find(ngx_str_t *name)
{
    ngx_uint_t               i;
    ngx_http_file_cache_t  **caches;

    if (ngx_http_file_caches == NULL) {
        return NULL;
    }

    caches = ngx_http_file_caches->elts;

    for (i = 0; i < ngx_http_file_caches->nelts; i++) {
        if (caches[i]->shm_zone->shm.name.len == name->len
            && ngx_memcmp(caches[i]->shm_zone->shm.name.data, name->data,
                          name->len)
               == 0)
        {
            return caches[i];
        }
    }

    return NULL;
}


static u_char *
ngx_http_api_cache_write(u_char *p, ngx_http_file_cache_t *cache,
    ngx_uint_t name)
{
    off_t                         size, max_size;
    ngx_atomic_uint_t             hit, miss, total, hit_ratio, miss_ratio;
    ngx_http_file_cache_stats_t  *stats;

    stats = &cache->sh->stats;

    hit = stats->responses[NGX_HTTP_CACHE_HIT - 1]
          + stats->responses[NGX_HTTP_CACHE_STALE - 1]
          + stats->responses[NGX_HTTP_CACHE_UPDATING - 1]
          + stats->responses[NGX_HTTP_CACHE_REVALIDATED - 1];

    miss = stats->responses[NGX_HTTP_CACHE_MISS - 1]
           + stats->responses[NGX_HTTP_CACHE_EXPIRED - 1]
           + stats->responses[NGX_HTTP_CACHE_BYPASS - 1];

    total = hit + miss;
    hit_ratio = total ? hit * 100 / total : 0;
    miss_ratio = total ? miss * 100 / total : 0;

    size = cache->sh->size * cache->bsize;
    max_size = cache->max_size * cache->bsize;

    if (name) {
        p = ngx_sprintf(p, "\"%V\":", &cache->shm_zone->shm.name);
    }

    p = ngx_sprintf(p, "{\"size\":%O,\"max_size\":%O,\"cold\":%s,",
                    size, max_size, cache->sh->cold ? "true" : "false");

    p = ngx_http_api_cache_write_group(p, "hit",
        stats->responses[NGX_HTTP_CACHE_HIT - 1], 0);
    *p++ = ',';
    p = ngx_http_api_cache_write_group(p, "stale",
        stats->responses[NGX_HTTP_CACHE_STALE - 1], 0);
    *p++ = ',';
    p = ngx_http_api_cache_write_group(p, "updating",
        stats->responses[NGX_HTTP_CACHE_UPDATING - 1], 0);
    *p++ = ',';
    p = ngx_http_api_cache_write_group(p, "revalidated",
        stats->responses[NGX_HTTP_CACHE_REVALIDATED - 1], 0);
    *p++ = ',';
    p = ngx_http_api_cache_write_group(p, "miss",
        stats->responses[NGX_HTTP_CACHE_MISS - 1], 1);
    *p++ = ',';
    p = ngx_http_api_cache_write_group(p, "expired",
        stats->responses[NGX_HTTP_CACHE_EXPIRED - 1], 1);
    *p++ = ',';
    p = ngx_http_api_cache_write_group(p, "bypass",
        stats->responses[NGX_HTTP_CACHE_BYPASS - 1], 1);

    p = ngx_sprintf(p, ",\"hit_ratio\":%uA,\"miss_ratio\":%uA}",
                    hit_ratio, miss_ratio);

    return p;
}


static u_char *
ngx_http_api_cache_write_group(u_char *p, const char *name,
    ngx_atomic_uint_t responses, ngx_uint_t written)
{
    if (written) {
        return ngx_sprintf(p, "\"%s\":{\"responses\":%uA,\"bytes\":0,"
                           "\"responses_written\":0,\"bytes_written\":0}",
                           name, responses);
    }

    return ngx_sprintf(p, "\"%s\":{\"responses\":%uA,\"bytes\":0}",
                       name, responses);
}


static void
ngx_http_api_cache_reset(ngx_http_file_cache_t *cache)
{
    ngx_shmtx_lock(&cache->shpool->mutex);
    ngx_memzero(&cache->sh->stats, sizeof(ngx_http_file_cache_stats_t));
    ngx_shmtx_unlock(&cache->shpool->mutex);
}

#endif
