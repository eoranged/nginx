
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_api_module.h"


#define NGX_HTTP_API_ZONE_SIZE  (8 * ngx_pagesize)


typedef struct {
    ngx_atomic_t                  processing;
    ngx_atomic_t                  requests;
    ngx_atomic_t                  responses[5];
    ngx_atomic_t                  responses_total;
    ngx_atomic_t                  discarded;
    ngx_atomic_t                  received;
    ngx_atomic_t                  sent;
} ngx_http_api_zone_shctx_t;


typedef struct {
    ngx_str_t                     name;
    ngx_slab_pool_t              *shpool;
    ngx_http_api_zone_shctx_t    *sh;
} ngx_http_api_zone_ctx_t;


typedef struct {
    ngx_array_t                  *zones;
    ngx_uint_t                    api;
} ngx_http_api_main_conf_t;


typedef struct {
    ngx_shm_zone_t               *status_zone;
    ngx_flag_t                    write;
} ngx_http_api_loc_conf_t;


typedef struct {
    ngx_http_request_t          *request;
    ngx_http_api_zone_shctx_t    *sh;
    unsigned                      active:1;
} ngx_http_api_processing_t;


typedef struct {
    ngx_http_api_zone_ctx_t      *zone;
    ngx_http_api_processing_t    *processing;
} ngx_http_api_request_ctx_t;


static ngx_int_t ngx_http_api_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_process(ngx_http_request_t *r);
static void ngx_http_api_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_nginx(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_server_zones(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_slabs(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_preaccess_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_log_handler(ngx_http_request_t *r);
static void ngx_http_api_processing_clear(ngx_http_request_t *r);
static void ngx_http_api_processing_done(ngx_http_api_processing_t *processing);
static void ngx_http_api_processing_cleanup(void *data);
static ngx_int_t ngx_http_api_validate_shared_memory(ngx_conf_t *cf);
static ngx_int_t ngx_http_api_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static void *ngx_http_api_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_api_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_api_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_api_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_api_status_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_api_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_api_commands[] = {

    { ngx_string("api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_api_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("status_zone"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_api_status_zone,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_api_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_api_init,                     /* postconfiguration */

    ngx_http_api_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_api_create_loc_conf,          /* create location configuration */
    ngx_http_api_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_api_module = {
    NGX_MODULE_V1,
    &ngx_http_api_module_ctx,              /* module context */
    ngx_http_api_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_api_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_api_loc_conf_t  *alcf;

    if (r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) {
        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            return rc;
        }

        return ngx_http_api_process(r);
    }

    if (!(r->method & (NGX_HTTP_POST|NGX_HTTP_PATCH|NGX_HTTP_DELETE))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_api_module);

    if (!alcf->write) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->method == NGX_HTTP_DELETE) {
        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            return rc;
        }

        return ngx_http_api_process(r);
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_api_body_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_api_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    rc = ngx_http_api_process(r);

    ngx_http_finalize_request(r, rc);
}


static ngx_int_t
ngx_http_api_process(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->uri.len == sizeof("/api/9/nginx") - 1
        && ngx_strncmp(r->uri.data, "/api/9/nginx",
                       sizeof("/api/9/nginx") - 1) == 0)
    {
        return ngx_http_api_nginx(r);
    }

    if (r->uri.len == sizeof("/api/9/http/server_zones") - 1
        && ngx_strncmp(r->uri.data, "/api/9/http/server_zones",
                       sizeof("/api/9/http/server_zones") - 1) == 0)
    {
        return ngx_http_api_server_zones(r);
    }

    if (r->uri.len == sizeof("/api/9/slabs") - 1
        && ngx_strncmp(r->uri.data, "/api/9/slabs",
                       sizeof("/api/9/slabs") - 1) == 0)
    {
        return ngx_http_api_slabs(r);
    }

    rc = ngx_http_api_caches(r);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = ngx_http_api_upstreams(r);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    return NGX_HTTP_NOT_FOUND;
}


ngx_int_t
ngx_http_api_send(ngx_http_request_t *r, ngx_buf_t *b)
{
    return ngx_http_api_send_status(r, b, NGX_HTTP_OK);
}


ngx_int_t
ngx_http_api_send_status(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_uint_t status)
{
    ngx_int_t    rc;
    ngx_chain_t  out;

    r->headers_out.status = status;
    r->headers_out.content_length_n = b->last - b->pos;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


ngx_int_t
ngx_http_api_send_no_content(ngx_http_request_t *r)
{
    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = 0;

    return ngx_http_send_header(r);
}


ngx_buf_t *
ngx_http_api_create_buffer(ngx_http_request_t *r)
{
    size_t                   size;
    ngx_uint_t               i;
    ngx_list_part_t         *part;
    ngx_shm_zone_t          *shm_zone;
    ngx_http_api_main_conf_t *amcf;

    size = 4096;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_api_module);
    if (amcf && amcf->zones) {
        size += amcf->zones->nelts * 1024;
    }

    part = (ngx_list_part_t *) &((ngx_cycle_t *) ngx_cycle)->shared_memory.part;
    shm_zone = part->elts;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            size += shm_zone[i].shm.name.len + 2048;
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        shm_zone = part->elts;
    }

    return ngx_create_temp_buf(r->pool, size);
}


ngx_int_t
ngx_http_api_read_body(ngx_http_request_t *r, ngx_str_t *body)
{
    u_char                    *p;
    size_t                     len;
    ngx_chain_t               *cl;
    ngx_http_request_body_t   *rb;

    body->len = 0;
    body->data = NULL;

    rb = r->request_body;
    if (rb == NULL || rb->bufs == NULL) {
        return NGX_OK;
    }

    if (rb->temp_file) {
        return NGX_ERROR;
    }

    len = 0;

    for (cl = rb->bufs; cl; cl = cl->next) {
        len += cl->buf->last - cl->buf->pos;
    }

    if (len == 0) {
        return NGX_OK;
    }

    body->data = ngx_pnalloc(r->pool, len);
    if (body->data == NULL) {
        return NGX_ERROR;
    }

    body->len = len;
    p = body->data;

    for (cl = rb->bufs; cl; cl = cl->next) {
        p = ngx_cpymem(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_nginx(ngx_http_request_t *r)
{
    ngx_buf_t  *b;

    b = ngx_http_api_create_buffer(r);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_sprintf(b->last,
                          "{\"version\":\"%s\",\"build\":\"%s\"}" CRLF,
                          NGINX_VERSION, NGINX_VER_BUILD);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_server_zones(ngx_http_request_t *r)
{
    ngx_buf_t                  *b;
    ngx_uint_t                  i;
    ngx_shm_zone_t            **zone;
    ngx_http_api_zone_ctx_t    *ctx;
    ngx_http_api_zone_shctx_t  *sh;
    ngx_http_api_main_conf_t   *amcf;

    b = ngx_http_api_create_buffer(r);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    amcf = ngx_http_get_module_main_conf(r, ngx_http_api_module);

    *b->last++ = '{';

    if (amcf && amcf->zones) {
        zone = amcf->zones->elts;

        for (i = 0; i < amcf->zones->nelts; i++) {
            ctx = zone[i]->data;
            sh = ctx->sh;

            if (i != 0) {
                *b->last++ = ',';
            }

            b->last = ngx_sprintf(b->last,
                "\"%V\":{\"processing\":%uA,\"requests\":%uA,"
                "\"responses\":{\"1xx\":%uA,\"2xx\":%uA,\"3xx\":%uA,"
                "\"4xx\":%uA,\"5xx\":%uA,\"total\":%uA},"
                "\"discarded\":%uA,\"received\":%uA,\"sent\":%uA}",
                &ctx->name, sh->processing, sh->requests, sh->responses[0],
                sh->responses[1], sh->responses[2], sh->responses[3],
                sh->responses[4], sh->responses_total, sh->discarded,
                sh->received, sh->sent);
        }
    }

    b->last = ngx_cpymem(b->last, "}" CRLF, sizeof("}" CRLF) - 1);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_slabs(ngx_http_request_t *r)
{
    size_t            size;
    ngx_buf_t        *b;
    ngx_uint_t        i, j, n;
    ngx_list_part_t  *part;
    ngx_shm_zone_t   *shm_zone;
    ngx_slab_pool_t  *shpool;

    b = ngx_http_api_create_buffer(r);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    n = 0;
    *b->last++ = '{';

    part = (ngx_list_part_t *) &((ngx_cycle_t *) ngx_cycle)->shared_memory.part;
    shm_zone = part->elts;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            if (shm_zone[i].shm.addr == NULL) {
                continue;
            }

            shpool = (ngx_slab_pool_t *) shm_zone[i].shm.addr;

            if (n++ != 0) {
                *b->last++ = ',';
            }

            b->last = ngx_sprintf(b->last,
                                  "\"%V\":{\"pages\":{\"used\":%ui,"
                                  "\"free\":%ui},\"slots\":{",
                                  &shm_zone[i].shm.name,
                                  (ngx_uint_t) (shpool->last - shpool->pages
                                                - shpool->pfree),
                                  shpool->pfree);

            for (j = 0, size = shpool->min_size;
                 size <= ngx_pagesize / 2;
                 j++, size <<= 1)
            {
                if (j != 0) {
                    *b->last++ = ',';
                }

                b->last = ngx_sprintf(b->last,
                                      "\"%uz\":{\"used\":%ui,\"free\":%ui,"
                                      "\"reqs\":%ui,\"fails\":%ui}",
                                      size, shpool->stats[j].used,
                                      shpool->stats[j].total
                                      - shpool->stats[j].used,
                                      shpool->stats[j].reqs,
                                      shpool->stats[j].fails);
            }

            b->last = ngx_cpymem(b->last, "}}", sizeof("}}") - 1);
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        shm_zone = part->elts;
    }

    b->last = ngx_cpymem(b->last, "}" CRLF, sizeof("}" CRLF) - 1);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_preaccess_handler(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t          *cln;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_api_loc_conf_t     *alcf;
    ngx_http_api_processing_t   *processing;
    ngx_http_api_request_ctx_t  *rctx;
    ngx_http_api_zone_ctx_t     *ctx;

    rctx = ngx_http_get_module_ctx(r, ngx_http_api_module);
    if (rctx != NULL) {
        return NGX_DECLINED;
    }

    ngx_http_api_processing_clear(r);

    if (r != r->main) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (!clcf->log_subrequest) {
            return NGX_DECLINED;
        }
    }

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_api_module);

    if (alcf->status_zone == NULL) {
        return NGX_DECLINED;
    }

    ctx = alcf->status_zone->data;
    if (ctx == NULL || ctx->sh == NULL) {
        return NGX_DECLINED;
    }

    rctx = ngx_pcalloc(r->pool, sizeof(ngx_http_api_request_ctx_t));
    if (rctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_api_processing_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    processing = cln->data;
    processing->request = r;
    processing->sh = ctx->sh;
    processing->active = 1;

    cln->handler = ngx_http_api_processing_cleanup;

    rctx->zone = ctx;
    rctx->processing = processing;
    ngx_http_set_ctx(r, rctx, ngx_http_api_module);

    (void) ngx_atomic_fetch_add(&ctx->sh->processing, 1);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_api_log_handler(ngx_http_request_t *r)
{
    ngx_uint_t                  status, n;
    ngx_http_api_loc_conf_t    *alcf;
    ngx_http_api_request_ctx_t  *rctx;
    ngx_http_api_zone_ctx_t    *ctx;
    ngx_http_api_zone_shctx_t  *sh;

    rctx = ngx_http_get_module_ctx(r, ngx_http_api_module);
    if (rctx != NULL) {
        ngx_http_api_processing_done(rctx->processing);
    }

    ngx_http_api_cache_log(r);

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_api_module);

    if (alcf->status_zone == NULL) {
        return NGX_OK;
    }

    ctx = alcf->status_zone->data;
    sh = ctx->sh;

    (void) ngx_atomic_fetch_add(&sh->requests, 1);

    if (r->connection->sent == 0) {
        (void) ngx_atomic_fetch_add(&sh->discarded, 1);

    } else {
        (void) ngx_atomic_fetch_add(&sh->responses_total, 1);

        status = r->headers_out.status;

        if (status >= 100 && status < 600) {
            n = status / 100 - 1;
            (void) ngx_atomic_fetch_add(&sh->responses[n], 1);
        }
    }

    if (r->request_length) {
        (void) ngx_atomic_fetch_add(&sh->received,
                                    (ngx_atomic_int_t) r->request_length);
    }

    if (r->connection->sent) {
        (void) ngx_atomic_fetch_add(&sh->sent,
                                    (ngx_atomic_int_t) r->connection->sent);
    }

    return NGX_OK;
}


static void
ngx_http_api_processing_clear(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t         *cln;
    ngx_http_api_processing_t  *processing;

    for (cln = r->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler != ngx_http_api_processing_cleanup) {
            continue;
        }

        processing = cln->data;

        if (processing->request == r) {
            ngx_http_api_processing_done(processing);
        }
    }
}


static void
ngx_http_api_processing_done(ngx_http_api_processing_t *processing)
{
    if (processing == NULL || !processing->active || processing->sh == NULL) {
        return;
    }

    processing->active = 0;
    (void) ngx_atomic_fetch_add(&processing->sh->processing, -1);
}


static void
ngx_http_api_processing_cleanup(void *data)
{
    ngx_http_api_processing_done(data);
}


ngx_int_t
ngx_http_api_valid_name(ngx_str_t *name)
{
    size_t  i;

    if (name->len == 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < name->len; i++) {
        if (name->data[i] < 0x20 || name->data[i] == '/'
            || name->data[i] == '"'
            || name->data[i] == '\\')
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_validate_shared_memory(ngx_conf_t *cf)
{
    ngx_uint_t       i;
    ngx_list_part_t *part;
    ngx_shm_zone_t  *shm_zone;

    part = (ngx_list_part_t *) &cf->cycle->shared_memory.part;
    shm_zone = part->elts;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            if (ngx_http_api_valid_name(&shm_zone[i].shm.name) != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid shared memory zone name \"%V\"",
                                   &shm_zone[i].shm.name);
                return NGX_ERROR;
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


static ngx_int_t
ngx_http_api_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                   len;
    ngx_http_api_zone_ctx_t *octx = data;
    ngx_http_api_zone_ctx_t *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_calloc(ctx->shpool, sizeof(ngx_http_api_zone_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    len = sizeof(" in status_zone \"\"") + ctx->name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in status_zone \"%V\"%Z",
                &ctx->name);

    return NGX_OK;
}


static void *
ngx_http_api_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_api_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NGX_HTTP_CACHE)
    ngx_http_file_caches = NULL;
#endif

    return conf;
}


static void *
ngx_http_api_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_api_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->status_zone = NGX_CONF_UNSET_PTR;
    conf->write = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_api_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_api_loc_conf_t *prev = parent;
    ngx_http_api_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->status_zone, prev->status_zone, NULL);
    ngx_conf_merge_value(conf->write, prev->write, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_api_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_api_loc_conf_t   *alcf = conf;

    ngx_str_t                 *value;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_api_main_conf_t  *amcf;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_api_module);
    amcf->api = 1;

    value = cf->args->elts;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[1].data, "write=on") == 0) {
            alcf->write = 1;

        } else if (ngx_strcmp(value[1].data, "write=off") == 0) {
            alcf->write = 0;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_api_handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_api_status_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_api_loc_conf_t  *alcf = conf;

    ngx_str_t                  *value;
    ngx_uint_t                  i;
    ngx_shm_zone_t            **zp;
    ngx_http_api_zone_ctx_t    *ctx;
    ngx_http_api_main_conf_t   *amcf;

    if (alcf->status_zone != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        return "zone name is empty";
    }

    if (ngx_http_api_valid_name(&value[1]) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid shared memory zone name \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_api_module);

    if (amcf->zones == NULL) {
        amcf->zones = ngx_array_create(cf->pool, 4, sizeof(ngx_shm_zone_t *));
        if (amcf->zones == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    alcf->status_zone = ngx_shared_memory_add(cf, &value[1],
                                              NGX_HTTP_API_ZONE_SIZE,
                                              &ngx_http_api_module);
    if (alcf->status_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (alcf->status_zone->data) {
        for (i = 0; i < amcf->zones->nelts; i++) {
            zp = amcf->zones->elts;
            if (zp[i] == alcf->status_zone) {
                return NGX_CONF_OK;
            }
        }

    } else {
        ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_zone_ctx_t));
        if (ctx == NULL) {
            return NGX_CONF_ERROR;
        }

        ctx->name = value[1];

        alcf->status_zone->init = ngx_http_api_init_zone;
        alcf->status_zone->data = ctx;
    }

    zp = ngx_array_push(amcf->zones);
    if (zp == NULL) {
        return NGX_CONF_ERROR;
    }

    *zp = alcf->status_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_api_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_api_main_conf_t   *amcf;
    ngx_http_core_main_conf_t  *cmcf;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_api_module);

    if (amcf->api
        && ngx_http_api_validate_shared_memory(cf) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (amcf->api
        && ngx_http_api_validate_upstream_names(cf) != NGX_OK)
    {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_api_preaccess_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_api_log_handler;

    return NGX_OK;
}
