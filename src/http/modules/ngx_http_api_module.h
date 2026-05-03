
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_API_MODULE_H_INCLUDED_
#define _NGX_HTTP_API_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t ngx_http_api_send(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_api_send_status(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_uint_t status);
ngx_buf_t *ngx_http_api_create_buffer(ngx_http_request_t *r);
ngx_int_t ngx_http_api_read_body(ngx_http_request_t *r, ngx_str_t *body);
ngx_int_t ngx_http_api_valid_name(ngx_str_t *name);

ngx_int_t ngx_http_api_upstreams(ngx_http_request_t *r);
ngx_int_t ngx_http_api_validate_upstream_names(ngx_conf_t *cf);


#endif /* _NGX_HTTP_API_MODULE_H_INCLUDED_ */
