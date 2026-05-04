/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_KEEPALIVE_MODULE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_KEEPALIVE_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


extern ngx_module_t  ngx_http_upstream_keepalive_module;


ngx_uint_t ngx_http_upstream_keepalive_configured(
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_keepalive_get_peer_no_cache(
    ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_HTTP_UPSTREAM_KEEPALIVE_MODULE_H_INCLUDED_ */
