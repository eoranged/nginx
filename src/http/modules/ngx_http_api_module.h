
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_API_MODULE_H_INCLUDED_
#define _NGX_HTTP_API_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


extern ngx_module_t  ngx_http_api_module;


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
    ngx_http_request_t           *request;
    ngx_buf_t                    *buf;
} ngx_http_api_prometheus_ctx_t;


ngx_int_t ngx_http_api_send(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_api_send_prometheus(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_api_send_status(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_uint_t status);
ngx_int_t ngx_http_api_send_no_content(ngx_http_request_t *r);
ngx_buf_t *ngx_http_api_create_buffer(ngx_http_request_t *r);
ngx_int_t ngx_http_api_read_body(ngx_http_request_t *r, ngx_str_t *body);
ngx_int_t ngx_http_api_valid_name(ngx_str_t *name);
ngx_int_t ngx_http_api_prometheus_append(ngx_http_api_prometheus_ctx_t *ctx,
    const char *fmt, ...);

ngx_int_t ngx_http_api_caches(ngx_http_request_t *r);
ngx_int_t ngx_http_api_prometheus_caches(ngx_http_api_prometheus_ctx_t *ctx);
void ngx_http_api_cache_log(ngx_http_request_t *r);
ngx_int_t ngx_http_api_upstreams(ngx_http_request_t *r);
ngx_int_t ngx_http_api_prometheus_upstreams(ngx_http_api_prometheus_ctx_t *ctx);
ngx_int_t ngx_http_api_validate_upstream_names(ngx_conf_t *cf);
ngx_int_t ngx_http_api_prometheus(ngx_http_request_t *r);


#endif /* _NGX_HTTP_API_MODULE_H_INCLUDED_ */
