
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


typedef struct {
    ngx_str_t                     server;
    ngx_uint_t                    server_set;

    ngx_int_t                     weight;
    ngx_uint_t                    weight_set;

    ngx_int_t                     max_conns;
    ngx_uint_t                    max_conns_set;

    ngx_int_t                     max_fails;
    ngx_uint_t                    max_fails_set;

    ngx_int_t                     fail_timeout;
    ngx_uint_t                    fail_timeout_set;

    ngx_int_t                     slow_start;
    ngx_uint_t                    slow_start_set;

    ngx_flag_t                    down;
    ngx_uint_t                    down_set;

    ngx_flag_t                    backup;
    ngx_uint_t                    backup_set;

    ngx_flag_t                    drain;
    ngx_uint_t                    drain_set;
} ngx_http_api_peer_conf_t;


static ngx_int_t ngx_http_api_http_upstreams(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_http_upstream(ngx_http_request_t *r,
    ngx_str_t *path);
static ngx_int_t ngx_http_api_http_upstream_list(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_http_servers(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_str_t *path);
static ngx_int_t ngx_http_api_http_server_get(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_uint_t id);
static ngx_int_t ngx_http_api_http_server_post(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_http_api_http_server_patch(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_uint_t id);
static ngx_int_t ngx_http_api_http_server_delete(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_uint_t id);
static ngx_http_upstream_srv_conf_t *ngx_http_api_http_find_upstream(
    ngx_http_request_t *r, ngx_str_t *name);
static ngx_http_upstream_rr_peer_t *ngx_http_api_http_find_peer(
    ngx_http_upstream_rr_peers_t *peers, ngx_uint_t id,
    ngx_http_upstream_rr_peers_t **peer_peers, ngx_uint_t *backup);
static ngx_uint_t ngx_http_api_http_peer_id(
    ngx_http_upstream_rr_peers_t *peers, ngx_http_upstream_rr_peer_t *peer);
static ngx_int_t ngx_http_api_http_add_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_http_api_peer_conf_t *pcf,
    ngx_buf_t *b);
static ngx_int_t ngx_http_api_http_alloc_backup(
    ngx_http_upstream_rr_peers_t *peers);
static void ngx_http_api_http_recount(ngx_http_upstream_rr_peers_t *peers);
static ngx_int_t ngx_http_api_http_duplicate(
    ngx_http_upstream_rr_peers_t *peers, ngx_str_t *server,
    ngx_uint_t backup);
static ngx_int_t ngx_http_api_http_duplicate_locked(
    ngx_http_upstream_rr_peers_t *peers, ngx_str_t *server);
static void ngx_http_api_http_peers_rlock(
    ngx_http_upstream_rr_peers_t *peers);
static void ngx_http_api_http_peers_wlock(
    ngx_http_upstream_rr_peers_t *peers);
static void ngx_http_api_http_peers_unlock(
    ngx_http_upstream_rr_peers_t *peers);
static u_char *ngx_http_api_http_write_peer(u_char *p,
    ngx_http_upstream_rr_peer_t *peer, ngx_uint_t id, ngx_uint_t backup);
static ngx_int_t ngx_http_api_http_write_servers(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_http_api_http_prometheus_peer(
    ngx_http_api_prometheus_ctx_t *ctx, ngx_str_t *upstream,
    ngx_http_upstream_rr_peer_t *peer);
static ngx_uint_t ngx_http_api_http_peer_state(
    ngx_http_upstream_rr_peer_t *peer);
static ngx_int_t ngx_http_api_http_move_peer(
    ngx_http_upstream_rr_peers_t *peers, ngx_http_upstream_rr_peers_t *src,
    ngx_http_upstream_rr_peer_t *peer, ngx_uint_t backup);
static void ngx_http_api_http_unlink_peer(
    ngx_http_upstream_rr_peers_t *peers, ngx_http_upstream_rr_peer_t *peer);

#if (NGX_STREAM_UPSTREAM_ZONE)
static ngx_int_t ngx_http_api_stream_upstreams(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_stream_upstream(ngx_http_request_t *r,
    ngx_str_t *path);
static ngx_int_t ngx_http_api_stream_upstream_list(ngx_http_request_t *r);
static ngx_int_t ngx_http_api_stream_servers(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_str_t *path);
static ngx_int_t ngx_http_api_stream_server_get(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_uint_t id);
static ngx_int_t ngx_http_api_stream_server_post(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_http_api_stream_server_patch(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_uint_t id);
static ngx_int_t ngx_http_api_stream_server_delete(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_uint_t id);
static ngx_stream_upstream_srv_conf_t *ngx_http_api_stream_find_upstream(
    ngx_str_t *name);
static ngx_stream_upstream_rr_peer_t *ngx_http_api_stream_find_peer(
    ngx_stream_upstream_rr_peers_t *peers, ngx_uint_t id,
    ngx_stream_upstream_rr_peers_t **peer_peers, ngx_uint_t *backup);
static ngx_uint_t ngx_http_api_stream_peer_id(
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *peer);
static ngx_int_t ngx_http_api_stream_add_peer(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_http_api_peer_conf_t *pcf,
    ngx_buf_t *b);
static ngx_int_t ngx_http_api_stream_alloc_backup(
    ngx_stream_upstream_rr_peers_t *peers);
static void ngx_http_api_stream_recount(ngx_stream_upstream_rr_peers_t *peers);
static ngx_int_t ngx_http_api_stream_duplicate(
    ngx_stream_upstream_rr_peers_t *peers, ngx_str_t *server,
    ngx_uint_t backup);
static ngx_int_t ngx_http_api_stream_duplicate_locked(
    ngx_stream_upstream_rr_peers_t *peers, ngx_str_t *server);
static void ngx_http_api_stream_peers_rlock(
    ngx_stream_upstream_rr_peers_t *peers);
static void ngx_http_api_stream_peers_wlock(
    ngx_stream_upstream_rr_peers_t *peers);
static void ngx_http_api_stream_peers_unlock(
    ngx_stream_upstream_rr_peers_t *peers);
static u_char *ngx_http_api_stream_write_peer(u_char *p,
    ngx_stream_upstream_rr_peer_t *peer, ngx_uint_t id, ngx_uint_t backup);
static ngx_int_t ngx_http_api_stream_write_servers(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_http_api_stream_prometheus_peer(
    ngx_http_api_prometheus_ctx_t *ctx, ngx_str_t *upstream,
    ngx_stream_upstream_rr_peer_t *peer);
static ngx_uint_t ngx_http_api_stream_peer_state(
    ngx_stream_upstream_rr_peer_t *peer);
static ngx_int_t ngx_http_api_stream_move_peer(
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peers_t *src,
    ngx_stream_upstream_rr_peer_t *peer, ngx_uint_t backup);
static void ngx_http_api_stream_unlink_peer(
    ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *peer);
#endif

static ngx_int_t ngx_http_api_parse_json(ngx_http_request_t *r,
    ngx_http_api_peer_conf_t *pcf, ngx_uint_t post);
static ngx_int_t ngx_http_api_json_string(u_char **pos, u_char *last,
    ngx_str_t *value);
static ngx_int_t ngx_http_api_json_bool(u_char **pos, u_char *last,
    ngx_flag_t *value);
static ngx_int_t ngx_http_api_json_int(u_char **pos, u_char *last,
    ngx_int_t *value);
static void ngx_http_api_json_skip_ws(u_char **pos, u_char *last);
static ngx_int_t ngx_http_api_parse_id(ngx_str_t *path, ngx_uint_t *id);
static ngx_int_t ngx_http_api_error(ngx_http_request_t *r, ngx_uint_t status,
    const char *text);
static ngx_buf_t *ngx_http_api_upstream_buffer(ngx_http_request_t *r,
    ngx_uint_t peers);
static ngx_int_t ngx_http_api_valid_label(ngx_str_t *name);
static u_char *ngx_http_api_time(u_char *p, ngx_msec_t msec);


ngx_int_t
ngx_http_api_upstreams(ngx_http_request_t *r)
{
    if (r->uri.len >= sizeof("/api/9/http/upstreams") - 1
        && ngx_strncmp(r->uri.data, "/api/9/http/upstreams",
                       sizeof("/api/9/http/upstreams") - 1)
           == 0)
    {
        return ngx_http_api_http_upstreams(r);
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
    if (r->uri.len >= sizeof("/api/9/stream/upstreams") - 1
        && ngx_strncmp(r->uri.data, "/api/9/stream/upstreams",
                       sizeof("/api/9/stream/upstreams") - 1)
           == 0)
    {
        return ngx_http_api_stream_upstreams(r);
    }
#endif

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_api_prometheus_upstreams(ngx_http_api_prometheus_ctx_t *ctx)
{
    ngx_uint_t                       i;
    ngx_http_upstream_rr_peer_t     *peer;
    ngx_http_upstream_rr_peers_t    *peers;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_http_upstream_main_conf_t   *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(((ngx_cycle_t *) ngx_cycle),
                                               ngx_http_upstream_module);
    if (umcf) {
        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            if (uscfp[i]->shm_zone == NULL || uscfp[i]->peer.data == NULL) {
                continue;
            }

            peers = uscfp[i]->peer.data;
            ngx_http_api_http_peers_rlock(peers);

            for (peer = peers->peer; peer; peer = peer->next) {
                if (ngx_http_api_http_prometheus_peer(ctx, &uscfp[i]->host,
                                                      peer) != NGX_OK)
                {
                    ngx_http_api_http_peers_unlock(peers);
                    return NGX_ERROR;
                }
            }

            if (peers->next) {
                for (peer = peers->next->peer; peer; peer = peer->next) {
                    if (ngx_http_api_http_prometheus_peer(ctx,
                        &uscfp[i]->host, peer) != NGX_OK)
                    {
                        ngx_http_api_http_peers_unlock(peers);
                        return NGX_ERROR;
                    }
                }
            }

            ngx_http_api_http_peers_unlock(peers);
        }
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
    {
        ngx_stream_upstream_rr_peer_t     *speer;
        ngx_stream_upstream_rr_peers_t    *speers;
        ngx_stream_upstream_srv_conf_t   **suscfp;
        ngx_stream_upstream_main_conf_t   *sumcf;

        sumcf = ngx_stream_cycle_get_module_main_conf(
                                            ((ngx_cycle_t *) ngx_cycle),
                                            ngx_stream_upstream_module);
        if (sumcf) {
            suscfp = sumcf->upstreams.elts;

            for (i = 0; i < sumcf->upstreams.nelts; i++) {
                if (suscfp[i]->shm_zone == NULL
                    || suscfp[i]->peer.data == NULL)
                {
                    continue;
                }

                speers = suscfp[i]->peer.data;
                ngx_http_api_stream_peers_rlock(speers);

                for (speer = speers->peer; speer; speer = speer->next) {
                    if (ngx_http_api_stream_prometheus_peer(ctx,
                        &suscfp[i]->host, speer) != NGX_OK)
                    {
                        ngx_http_api_stream_peers_unlock(speers);
                        return NGX_ERROR;
                    }
                }

                if (speers->next) {
                    for (speer = speers->next->peer; speer;
                         speer = speer->next)
                    {
                        if (ngx_http_api_stream_prometheus_peer(ctx,
                            &suscfp[i]->host, speer) != NGX_OK)
                        {
                            ngx_http_api_stream_peers_unlock(speers);
                            return NGX_ERROR;
                        }
                    }
                }

                ngx_http_api_stream_peers_unlock(speers);
            }
        }
    }
#endif

    return NGX_OK;
}


ngx_int_t
ngx_http_api_validate_upstream_names(ngx_conf_t *cf)
{
    ngx_uint_t                       i;
    ngx_str_t                       *server;
    ngx_http_upstream_rr_peer_t     *peer;
    ngx_http_upstream_rr_peers_t    *peers;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_http_upstream_main_conf_t   *umcf;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    if (umcf) {
        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            if (ngx_http_api_valid_name(&uscfp[i]->host) != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid upstream name \"%V\"",
                                   &uscfp[i]->host);
                return NGX_ERROR;
            }

            peers = uscfp[i]->peer.data;
            if (peers == NULL) {
                continue;
            }

            for (peer = peers->peer; peer; peer = peer->next) {
                server = peer->server.len ? &peer->server : &peer->name;

                if (ngx_http_api_valid_label(server) != NGX_OK) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid upstream server name \"%V\"",
                                       server);
                    return NGX_ERROR;
                }
            }

            if (peers->next) {
                for (peer = peers->next->peer; peer; peer = peer->next) {
                    server = peer->server.len ? &peer->server : &peer->name;

                    if (ngx_http_api_valid_label(server) != NGX_OK) {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                           "invalid upstream server name "
                                           "\"%V\"", server);
                        return NGX_ERROR;
                    }
                }
            }
        }
    }

#if (NGX_STREAM_UPSTREAM_ZONE)
    {
        ngx_stream_upstream_rr_peer_t     *speer;
        ngx_stream_upstream_rr_peers_t    *speers;
        ngx_stream_upstream_srv_conf_t   **suscfp;
        ngx_stream_upstream_main_conf_t   *sumcf;

        sumcf = ngx_stream_cycle_get_module_main_conf(cf->cycle,
                                                ngx_stream_upstream_module);
        if (sumcf) {
            suscfp = sumcf->upstreams.elts;

            for (i = 0; i < sumcf->upstreams.nelts; i++) {
                if (ngx_http_api_valid_name(&suscfp[i]->host) != NGX_OK) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid upstream name \"%V\"",
                                       &suscfp[i]->host);
                    return NGX_ERROR;
                }

                speers = suscfp[i]->peer.data;
                if (speers == NULL) {
                    continue;
                }

                for (speer = speers->peer; speer; speer = speer->next) {
                    server = speer->server.len ? &speer->server
                                               : &speer->name;

                    if (ngx_http_api_valid_label(server) != NGX_OK) {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                           "invalid upstream server name "
                                           "\"%V\"", server);
                        return NGX_ERROR;
                    }
                }

                if (speers->next) {
                    for (speer = speers->next->peer; speer;
                         speer = speer->next)
                    {
                        server = speer->server.len ? &speer->server
                                                   : &speer->name;

                        if (ngx_http_api_valid_label(server) != NGX_OK) {
                            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                               "invalid upstream server name "
                                               "\"%V\"", server);
                            return NGX_ERROR;
                        }
                    }
                }
            }
        }
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_http_upstreams(ngx_http_request_t *r)
{
    ngx_str_t  path;

    path.data = r->uri.data + sizeof("/api/9/http/upstreams") - 1;
    path.len = r->uri.len - (sizeof("/api/9/http/upstreams") - 1);

    if (path.len == 0 || (path.len == 1 && path.data[0] == '/')) {
        return ngx_http_api_http_upstream_list(r);
    }

    if (path.data[0] != '/') {
        return NGX_HTTP_NOT_FOUND;
    }

    path.data++;
    path.len--;

    return ngx_http_api_http_upstream(r, &path);
}


static ngx_int_t
ngx_http_api_http_upstream(ngx_http_request_t *r, ngx_str_t *path)
{
    u_char                         *p, *last;
    ngx_str_t                       name, rest;
    ngx_http_upstream_srv_conf_t   *uscf;

    p = path->data;
    last = path->data + path->len;

    while (p < last && *p != '/') {
        p++;
    }

    name.data = path->data;
    name.len = p - path->data;

    if (name.len == 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    uscf = ngx_http_api_http_find_upstream(r, &name);
    if (uscf == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (p == last) {
        return ngx_http_api_http_write_servers(r, uscf);
    }

    rest.data = p + 1;
    rest.len = last - p - 1;

    if (rest.len < sizeof("servers") - 1
        || ngx_strncmp(rest.data, "servers", sizeof("servers") - 1) != 0)
    {
        return NGX_HTTP_NOT_FOUND;
    }

    rest.data += sizeof("servers") - 1;
    rest.len -= sizeof("servers") - 1;

    return ngx_http_api_http_servers(r, uscf, &rest);
}


static ngx_int_t
ngx_http_api_http_upstream_list(ngx_http_request_t *r)
{
    ngx_buf_t                       *b;
    ngx_uint_t                       count, config, i, n;
    ngx_http_upstream_rr_peers_t    *peers;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_http_upstream_main_conf_t   *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    b = ngx_http_api_upstream_buffer(r, umcf ? umcf->upstreams.nelts : 0);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *b->last++ = '{';

    if (umcf) {
        uscfp = umcf->upstreams.elts;

        for (i = 0, n = 0; i < umcf->upstreams.nelts; i++) {
            peers = uscfp[i]->peer.data;
            config = 0;
            count = 0;

            if (peers) {
                ngx_http_api_http_peers_rlock(peers);
                config = peers->config ? *peers->config : 0;
                count = peers->number
                        + (peers->next ? peers->next->number : 0);
                ngx_http_api_http_peers_unlock(peers);
            }

            if (n++ != 0) {
                *b->last++ = ',';
            }

            b->last = ngx_sprintf(b->last,
                "\"%V\":{\"config\":%ui,\"peers\":%ui}",
                &uscfp[i]->host, config, count);
        }
    }

    b->last = ngx_cpymem(b->last, "}" CRLF, sizeof("}" CRLF) - 1);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_http_servers(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_str_t *path)
{
    ngx_uint_t  id;
    ngx_str_t   s;

    if (uscf->shm_zone == NULL) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST,
                                  "upstream zone is required");
    }

    if (path->len == 0 || (path->len == 1 && path->data[0] == '/')) {
        if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
            return ngx_http_api_http_write_servers(r, uscf);
        }

        if (r->method == NGX_HTTP_POST) {
            return ngx_http_api_http_server_post(r, uscf);
        }

        return NGX_HTTP_NOT_ALLOWED;
    }

    if (path->data[0] != '/') {
        return NGX_HTTP_NOT_FOUND;
    }

    s.data = path->data + 1;
    s.len = path->len - 1;

    if (ngx_http_api_parse_id(&s, &id) != NGX_OK) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
        return ngx_http_api_http_server_get(r, uscf, id);
    }

    if (r->method == NGX_HTTP_PATCH) {
        return ngx_http_api_http_server_patch(r, uscf, id);
    }

    if (r->method == NGX_HTTP_DELETE) {
        return ngx_http_api_http_server_delete(r, uscf, id);
    }

    return NGX_HTTP_NOT_ALLOWED;
}


static ngx_int_t
ngx_http_api_http_server_get(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_uint_t id)
{
    ngx_buf_t                     *b;
    ngx_uint_t                     backup;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers, *peer_peers;

    peers = uscf->peer.data;

    ngx_http_api_http_peers_rlock(peers);

    peer = ngx_http_api_http_find_peer(peers, id, &peer_peers, &backup);
    if (peer == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_HTTP_NOT_FOUND;
    }

    b = ngx_http_api_upstream_buffer(r, 1);
    if (b == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_http_api_http_write_peer(b->last, peer, id, backup);
    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ngx_http_api_http_peers_unlock(peers);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_http_server_post(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_buf_t                     *b;
    ngx_int_t                      rc;
    ngx_http_api_peer_conf_t       pcf;

    if (ngx_http_api_parse_json(r, &pcf, 1) != NGX_OK) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST, "invalid json");
    }

    if (pcf.backup_set == 0) {
        pcf.backup = 0;
    }

#if !(NGX_HTTP_UPSTREAM_STICKY)
    if (pcf.drain_set) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST,
                                  "drain is not supported");
    }
#endif

    if (ngx_http_api_http_duplicate(uscf->peer.data, &pcf.server, pcf.backup))
    {
        return ngx_http_api_error(r, NGX_HTTP_CONFLICT, "duplicate server");
    }

    b = ngx_http_api_upstream_buffer(r, 1);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_api_http_add_peer(r, uscf, &pcf, b);

    if (rc == NGX_BUSY) {
        return ngx_http_api_error(r, NGX_HTTP_CONFLICT, "duplicate server");
    }

    if (rc != NGX_OK) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST, "invalid server");
    }

    return ngx_http_api_send_status(r, b, NGX_HTTP_CREATED);
}


static ngx_int_t
ngx_http_api_http_server_patch(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_uint_t id)
{
    ngx_buf_t                     *b;
    ngx_uint_t                     backup;
    ngx_http_api_peer_conf_t       pcf;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers, *peer_peers;

    if (ngx_http_api_parse_json(r, &pcf, 0) != NGX_OK || pcf.server_set) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST, "invalid json");
    }

    peers = uscf->peer.data;

    ngx_http_api_http_peers_wlock(peers);

    peer = ngx_http_api_http_find_peer(peers, id, &peer_peers, &backup);
    if (peer == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_HTTP_NOT_FOUND;
    }

    if (pcf.backup_set && (ngx_uint_t) pcf.backup != backup) {
        if (ngx_http_api_http_move_peer(peers, peer_peers, peer, pcf.backup)
            != NGX_OK)
        {
            ngx_http_api_http_peers_unlock(peers);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        peer_peers = pcf.backup ? peers->next : peers;
        backup = pcf.backup;
    }

    if (pcf.weight_set) {
        peer->weight = pcf.weight;
        peer->effective_weight = pcf.weight;
    }

    if (pcf.max_conns_set) {
        peer->max_conns = pcf.max_conns;
    }

    if (pcf.max_fails_set) {
        peer->max_fails = pcf.max_fails;
    }

    if (pcf.fail_timeout_set) {
        peer->fail_timeout = pcf.fail_timeout;
    }

    if (pcf.slow_start_set) {
        peer->slow_start = pcf.slow_start;
        peer->start_time = ngx_current_msec;
    }

    if (pcf.down_set) {
        if (pcf.down) {
            peer->down |= NGX_HTTP_UPSTREAM_FAILED;
        } else {
            peer->down &= ~NGX_HTTP_UPSTREAM_FAILED;
        }
    }

    if (pcf.drain_set) {
#if (NGX_HTTP_UPSTREAM_STICKY)
        if (pcf.drain) {
            peer->down |= NGX_HTTP_UPSTREAM_DRAINING;
        } else {
            peer->down &= ~NGX_HTTP_UPSTREAM_DRAINING;
        }
#else
        ngx_http_api_http_peers_unlock(peers);
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST,
                                  "drain is not supported");
#endif
    }

    if (peers->config) {
        (*peers->config)++;
    }

    ngx_http_api_http_recount(peers);
    id = ngx_http_api_http_peer_id(peers, peer);

    b = ngx_http_api_upstream_buffer(r, 1);
    if (b == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_http_api_http_write_peer(b->last, peer, id, backup);
    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ngx_http_api_http_peers_unlock(peers);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_http_server_delete(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_uint_t id)
{
    ngx_buf_t                     *b;
    ngx_uint_t                     backup;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers, *peer_peers;

    peers = uscf->peer.data;

    ngx_http_api_http_peers_wlock(peers);

    peer = ngx_http_api_http_find_peer(peers, id, &peer_peers, &backup);
    if (peer == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_HTTP_NOT_FOUND;
    }

    b = ngx_http_api_upstream_buffer(r, 1);
    if (b == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_http_api_http_write_peer(b->last, peer, id, backup);
    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ngx_http_api_http_unlink_peer(peer_peers, peer);

    if (peers->config) {
        (*peers->config)++;
    }

    ngx_http_api_http_recount(peers);

    ngx_http_upstream_rr_peer_free(peer_peers, peer);

    ngx_http_api_http_peers_unlock(peers);

    return ngx_http_api_send(r, b);
}


static ngx_http_upstream_srv_conf_t *
ngx_http_api_http_find_upstream(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t                       i;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_http_upstream_main_conf_t   *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NULL;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == name->len
            && ngx_memcmp(uscfp[i]->host.data, name->data, name->len) == 0)
        {
            return uscfp[i];
        }
    }

    return NULL;
}


static ngx_http_upstream_rr_peer_t *
ngx_http_api_http_find_peer(ngx_http_upstream_rr_peers_t *peers, ngx_uint_t id,
    ngx_http_upstream_rr_peers_t **peer_peers, ngx_uint_t *backup)
{
    ngx_uint_t                    i;
    ngx_http_upstream_rr_peer_t  *peer;

    i = 0;

    for (peer = peers->peer; peer; peer = peer->next, i++) {
        if (i == id) {
            *peer_peers = peers;
            *backup = 0;
            return peer;
        }
    }

    if (peers->next == NULL) {
        return NULL;
    }

    for (peer = peers->next->peer; peer; peer = peer->next, i++) {
        if (i == id) {
            *peer_peers = peers->next;
            *backup = 1;
            return peer;
        }
    }

    return NULL;
}


static ngx_uint_t
ngx_http_api_http_peer_id(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peer_t *peer)
{
    ngx_uint_t                    id;
    ngx_http_upstream_rr_peer_t  *p;

    id = 0;

    for (p = peers->peer; p; p = p->next, id++) {
        if (p == peer) {
            return id;
        }
    }

    if (peers->next) {
        for (p = peers->next->peer; p; p = p->next, id++) {
            if (p == peer) {
                return id;
            }
        }
    }

    return id;
}


static ngx_int_t
ngx_http_api_http_add_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_http_api_peer_conf_t *pcf,
    ngx_buf_t *b)
{
    ngx_url_t                     u;
    ngx_str_t                     server;
    ngx_uint_t                    down, id;
    ngx_http_upstream_rr_peer_t  *peer, **peerp;
    ngx_http_upstream_rr_peers_t *peers, *target;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = pcf->server;
    u.default_port = 80;

    if (ngx_parse_url(r->pool, &u) != NGX_OK || u.naddrs == 0) {
        return NGX_ERROR;
    }

    server = pcf->server;
    peers = uscf->peer.data;

    ngx_http_api_http_peers_wlock(peers);

    if (pcf->backup) {
        if (peers->next == NULL) {
            if (ngx_http_api_http_alloc_backup(peers) != NGX_OK) {
                ngx_http_api_http_peers_unlock(peers);
                return NGX_ERROR;
            }

            ngx_http_upstream_rr_peers_wlock(peers->next);
        }

        target = peers->next;

    } else {
        target = peers;
    }

    if (ngx_http_api_http_duplicate_locked(target, &server)) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_BUSY;
    }

    peer = ngx_slab_calloc(target->shpool, sizeof(ngx_http_upstream_rr_peer_t));
    if (peer == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_ERROR;
    }

    peer->sockaddr = ngx_slab_calloc(target->shpool, sizeof(ngx_sockaddr_t));
    peer->name.data = ngx_slab_calloc(target->shpool, NGX_SOCKADDR_STRLEN);
    peer->server.data = ngx_slab_alloc(target->shpool, server.len);

#if (NGX_HTTP_UPSTREAM_SID)
    peer->sid.data = ngx_slab_calloc(target->shpool,
                                     NGX_HTTP_UPSTREAM_SID_LEN);
#endif

    if (peer->sockaddr == NULL || peer->name.data == NULL
        || peer->server.data == NULL
#if (NGX_HTTP_UPSTREAM_SID)
        || peer->sid.data == NULL
#endif
       )
    {
        if (peer->sockaddr) {
            ngx_slab_free(target->shpool, peer->sockaddr);
        }

        if (peer->name.data) {
            ngx_slab_free(target->shpool, peer->name.data);
        }

        if (peer->server.data) {
            ngx_slab_free(target->shpool, peer->server.data);
        }

#if (NGX_HTTP_UPSTREAM_SID)
        if (peer->sid.data) {
            ngx_slab_free(target->shpool, peer->sid.data);
        }
#endif

        ngx_slab_free(target->shpool, peer);
        ngx_http_api_http_peers_unlock(peers);
        return NGX_ERROR;
    }

    ngx_memcpy(peer->sockaddr, u.addrs[0].sockaddr, u.addrs[0].socklen);
    peer->socklen = u.addrs[0].socklen;
    peer->name.len = ngx_sock_ntop(peer->sockaddr, peer->socklen,
                                   peer->name.data, NGX_SOCKADDR_STRLEN, 1);

    ngx_memcpy(peer->server.data, server.data, server.len);
    peer->server.len = server.len;

    peer->weight = pcf->weight_set ? pcf->weight : 1;
    peer->effective_weight = peer->weight;
    peer->current_weight = 0;
    peer->max_conns = pcf->max_conns_set ? pcf->max_conns : 0;
    peer->max_fails = pcf->max_fails_set ? pcf->max_fails : 1;
    peer->fail_timeout = pcf->fail_timeout_set ? pcf->fail_timeout : 10;
    peer->slow_start = pcf->slow_start_set ? pcf->slow_start : 0;
    peer->start_time = ngx_current_msec;

    down = 0;
    if (pcf->down_set && pcf->down) {
        down |= NGX_HTTP_UPSTREAM_FAILED;
    }

#if (NGX_HTTP_UPSTREAM_STICKY)
    if (pcf->drain_set && pcf->drain) {
        down |= NGX_HTTP_UPSTREAM_DRAINING;
    }
#endif

    peer->down = down;

#if (NGX_HTTP_UPSTREAM_SID)
    ngx_http_upstream_init_round_robin_sid(peer, NULL);
#endif

    for (peerp = &target->peer; *peerp; peerp = &(*peerp)->next) {
        /* void */
    }

    *peerp = peer;

    if (peers->config) {
        (*peers->config)++;
    }

    ngx_http_api_http_recount(peers);

    id = (target == peers) ? target->number - 1
                           : peers->number + target->number - 1;

    b->last = ngx_http_api_http_write_peer(b->last, peer, id, pcf->backup);
    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ngx_http_api_http_peers_unlock(peers);

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_http_alloc_backup(ngx_http_upstream_rr_peers_t *peers)
{
    ngx_http_upstream_rr_peers_t  *backup;

    backup = ngx_slab_calloc(peers->shpool,
                             sizeof(ngx_http_upstream_rr_peers_t));
    if (backup == NULL) {
        return NGX_ERROR;
    }

    backup->shpool = peers->shpool;
    backup->config = peers->config;
    backup->name = peers->name;

    peers->next = backup;

    return NGX_OK;
}


static void
ngx_http_api_http_recount(ngx_http_upstream_rr_peers_t *peers)
{
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *p;

    for (p = peers; p; p = p->next) {
        p->number = 0;
        p->tries = 0;
        p->total_weight = 0;
        p->single = 0;

        for (peer = p->peer; peer; peer = peer->next) {
            p->number++;
            p->total_weight += peer->weight;
            p->tries += (peer->down == 0);
        }

        p->weighted = (p->total_weight != p->number);
    }

    if (peers->number == 1
        && (peers->next == NULL || peers->next->number == 0))
    {
        peers->single = 1;
    }
}


static ngx_int_t
ngx_http_api_http_duplicate(ngx_http_upstream_rr_peers_t *peers,
    ngx_str_t *server, ngx_uint_t backup)
{
    ngx_int_t                     rc;
    ngx_http_upstream_rr_peers_t  *target;

    ngx_http_api_http_peers_rlock(peers);

    target = backup ? peers->next : peers;
    if (target == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return 0;
    }

    rc = ngx_http_api_http_duplicate_locked(target, server);

    ngx_http_api_http_peers_unlock(peers);

    return rc;
}


static ngx_int_t
ngx_http_api_http_duplicate_locked(ngx_http_upstream_rr_peers_t *peers,
    ngx_str_t *server)
{
    ngx_http_upstream_rr_peer_t  *peer;

    for (peer = peers->peer; peer; peer = peer->next) {
        if (peer->server.len == server->len
            && ngx_memcmp(peer->server.data, server->data, server->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static void
ngx_http_api_http_peers_rlock(ngx_http_upstream_rr_peers_t *peers)
{
    ngx_http_upstream_rr_peers_rlock(peers);

    if (peers->next) {
        ngx_http_upstream_rr_peers_rlock(peers->next);
    }
}


static void
ngx_http_api_http_peers_wlock(ngx_http_upstream_rr_peers_t *peers)
{
    ngx_http_upstream_rr_peers_wlock(peers);

    if (peers->next) {
        ngx_http_upstream_rr_peers_wlock(peers->next);
    }
}


static void
ngx_http_api_http_peers_unlock(ngx_http_upstream_rr_peers_t *peers)
{
    if (peers->next) {
        ngx_http_upstream_rr_peers_unlock(peers->next);
    }

    ngx_http_upstream_rr_peers_unlock(peers);
}


static u_char *
ngx_http_api_http_write_peer(u_char *p, ngx_http_upstream_rr_peer_t *peer,
    ngx_uint_t id, ngx_uint_t backup)
{
    ngx_str_t  *server;

    server = peer->server.len ? &peer->server : &peer->name;

    p = ngx_sprintf(p,
        "{\"id\":%ui,\"server\":\"%V\",\"name\":\"%V\","
        "\"backup\":%s,\"weight\":%i,\"max_conns\":%ui,"
        "\"max_fails\":%ui,\"fail_timeout\":\"%Ts\",",
        id, server, &peer->name, backup ? "true" : "false",
        peer->weight, peer->max_conns, peer->max_fails, peer->fail_timeout);

    p = ngx_cpymem(p, "\"slow_start\":\"", sizeof("\"slow_start\":\"") - 1);
    p = ngx_http_api_time(p, peer->slow_start);

    p = ngx_sprintf(p, "\",\"down\":%s",
                    (peer->down & NGX_HTTP_UPSTREAM_FAILED)
                    ? "true" : "false");

#if (NGX_HTTP_UPSTREAM_STICKY)
    p = ngx_sprintf(p, ",\"drain\":%s",
                    (peer->down & NGX_HTTP_UPSTREAM_DRAINING)
                    ? "true" : "false");
#else
    p = ngx_cpymem(p, ",\"drain\":false", sizeof(",\"drain\":false") - 1);
#endif

    *p++ = '}';

    return p;
}


static ngx_int_t
ngx_http_api_http_write_servers(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_buf_t                     *b;
    ngx_uint_t                     id;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;

    if (uscf->shm_zone == NULL) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST,
                                  "upstream zone is required");
    }

    peers = uscf->peer.data;

    ngx_http_api_http_peers_rlock(peers);

    b = ngx_http_api_upstream_buffer(r, peers->number
                                        + (peers->next
                                           ? peers->next->number : 0));
    if (b == NULL) {
        ngx_http_api_http_peers_unlock(peers);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *b->last++ = '[';
    id = 0;

    for (peer = peers->peer; peer; peer = peer->next, id++) {
        if (id != 0) {
            *b->last++ = ',';
        }

        b->last = ngx_http_api_http_write_peer(b->last, peer, id, 0);
    }

    if (peers->next) {
        for (peer = peers->next->peer; peer; peer = peer->next, id++) {
            if (id != 0) {
                *b->last++ = ',';
            }

            b->last = ngx_http_api_http_write_peer(b->last, peer, id, 1);
        }
    }

    b->last = ngx_cpymem(b->last, "]" CRLF, sizeof("]" CRLF) - 1);

    ngx_http_api_http_peers_unlock(peers);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_http_prometheus_peer(ngx_http_api_prometheus_ctx_t *ctx,
    ngx_str_t *upstream,
    ngx_http_upstream_rr_peer_t *peer)
{
    ngx_str_t           *server;
    ngx_atomic_uint_t    responses[5];

    server = peer->server.len ? &peer->server : &peer->name;

    responses[0] = peer->responses[0];
    responses[1] = peer->responses[1];
    responses[2] = peer->responses[2];
    responses[3] = peer->responses[3];
    responses[4] = peer->responses[4];

    if (responses[0] == 0 && responses[1] == 0 && responses[2] == 0
        && responses[3] == 0 && responses[4] == 0
        && peer->requests && peer->received)
    {
        responses[1] = peer->requests;
    }

    if (ngx_http_api_prometheus_append(ctx, "nginxplus_upstream_server_state"
        "{server=\"%V\",upstream=\"%V\"} %ui" CRLF,
        server, upstream, ngx_http_api_http_peer_state(peer)) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_active"
        "{server=\"%V\",upstream=\"%V\"} %ui" CRLF,
        server, upstream, peer->conns) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_limit"
        "{server=\"%V\",upstream=\"%V\"} %ui" CRLF,
        server, upstream, peer->max_conns) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_requests"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->requests) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_responses"
        "{code=\"1xx\",server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, responses[0]) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_responses"
        "{code=\"2xx\",server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, responses[1]) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_responses"
        "{code=\"3xx\",server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, responses[2]) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_responses"
        "{code=\"4xx\",server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, responses[3]) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_responses"
        "{code=\"5xx\",server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, responses[4]) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_sent"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->sent) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_received"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->received) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_fails"
        "{server=\"%V\",upstream=\"%V\"} %ui" CRLF,
        server, upstream, peer->fails) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_unavail"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->unavail) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_header_time"
        "{server=\"%V\",upstream=\"%V\"} %M" CRLF,
        server, upstream, peer->header_time) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_response_time"
        "{server=\"%V\",upstream=\"%V\"} %M" CRLF,
        server, upstream, peer->response_time) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_health_checks_checks"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->health_checks) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_health_checks_fails"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->health_fails) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_upstream_server_health_checks_unhealthy"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->health_unhealthy) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_api_http_peer_state(ngx_http_upstream_rr_peer_t *peer)
{
#if (NGX_HTTP_UPSTREAM_STICKY)
    if (peer->down & NGX_HTTP_UPSTREAM_DRAINING) {
        return 2;
    }
#endif

    if (peer->down & NGX_HTTP_UPSTREAM_FAILED) {
        return 3;
    }

    if (peer->max_fails && peer->fails >= peer->max_fails) {
        return 4;
    }

    if (peer->down & NGX_HTTP_UPSTREAM_HC_DOWN) {
        return 6;
    }

    return 1;
}


static ngx_int_t
ngx_http_api_http_move_peer(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peers_t *src, ngx_http_upstream_rr_peer_t *peer,
    ngx_uint_t backup)
{
    ngx_http_upstream_rr_peer_t  **peerp;
    ngx_http_upstream_rr_peers_t  *dst;

    if (backup) {
        if (peers->next == NULL) {
            if (ngx_http_api_http_alloc_backup(peers) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_http_upstream_rr_peers_wlock(peers->next);
        }

        dst = peers->next;

    } else {
        dst = peers;
    }

    if (src == dst) {
        return NGX_OK;
    }

    ngx_http_api_http_unlink_peer(src, peer);

    peer->next = NULL;

    for (peerp = &dst->peer; *peerp; peerp = &(*peerp)->next) {
        /* void */
    }

    *peerp = peer;

    return NGX_OK;
}


static void
ngx_http_api_http_unlink_peer(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peer_t *peer)
{
    ngx_http_upstream_rr_peer_t  **peerp;

    for (peerp = &peers->peer; *peerp; peerp = &(*peerp)->next) {
        if (*peerp == peer) {
            *peerp = peer->next;
            peer->next = NULL;
            return;
        }
    }
}


#if (NGX_STREAM_UPSTREAM_ZONE)

static ngx_int_t
ngx_http_api_stream_upstreams(ngx_http_request_t *r)
{
    ngx_str_t  path;

    path.data = r->uri.data + sizeof("/api/9/stream/upstreams") - 1;
    path.len = r->uri.len - (sizeof("/api/9/stream/upstreams") - 1);

    if (path.len == 0 || (path.len == 1 && path.data[0] == '/')) {
        return ngx_http_api_stream_upstream_list(r);
    }

    if (path.data[0] != '/') {
        return NGX_HTTP_NOT_FOUND;
    }

    path.data++;
    path.len--;

    return ngx_http_api_stream_upstream(r, &path);
}


static ngx_int_t
ngx_http_api_stream_upstream(ngx_http_request_t *r, ngx_str_t *path)
{
    u_char                           *p, *last;
    ngx_str_t                         name, rest;
    ngx_stream_upstream_srv_conf_t   *uscf;

    p = path->data;
    last = path->data + path->len;

    while (p < last && *p != '/') {
        p++;
    }

    name.data = path->data;
    name.len = p - path->data;

    if (name.len == 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    uscf = ngx_http_api_stream_find_upstream(&name);
    if (uscf == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (p == last) {
        return ngx_http_api_stream_write_servers(r, uscf);
    }

    rest.data = p + 1;
    rest.len = last - p - 1;

    if (rest.len < sizeof("servers") - 1
        || ngx_strncmp(rest.data, "servers", sizeof("servers") - 1) != 0)
    {
        return NGX_HTTP_NOT_FOUND;
    }

    rest.data += sizeof("servers") - 1;
    rest.len -= sizeof("servers") - 1;

    return ngx_http_api_stream_servers(r, uscf, &rest);
}


static ngx_int_t
ngx_http_api_stream_upstream_list(ngx_http_request_t *r)
{
    ngx_buf_t                         *b;
    ngx_uint_t                         count, config, i, n;
    ngx_stream_upstream_rr_peers_t    *peers;
    ngx_stream_upstream_srv_conf_t   **uscfp;
    ngx_stream_upstream_main_conf_t   *umcf;

    umcf = ngx_stream_cycle_get_module_main_conf(((ngx_cycle_t *) ngx_cycle),
                                                 ngx_stream_upstream_module);

    b = ngx_http_api_upstream_buffer(r, umcf ? umcf->upstreams.nelts : 0);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *b->last++ = '{';

    if (umcf) {
        uscfp = umcf->upstreams.elts;

        for (i = 0, n = 0; i < umcf->upstreams.nelts; i++) {
            peers = uscfp[i]->peer.data;
            config = 0;
            count = 0;

            if (peers) {
                ngx_http_api_stream_peers_rlock(peers);
                config = peers->config ? *peers->config : 0;
                count = peers->number
                        + (peers->next ? peers->next->number : 0);
                ngx_http_api_stream_peers_unlock(peers);
            }

            if (n++ != 0) {
                *b->last++ = ',';
            }

            b->last = ngx_sprintf(b->last,
                "\"%V\":{\"config\":%ui,\"peers\":%ui}",
                &uscfp[i]->host, config, count);
        }
    }

    b->last = ngx_cpymem(b->last, "}" CRLF, sizeof("}" CRLF) - 1);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_stream_servers(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_str_t *path)
{
    ngx_uint_t  id;
    ngx_str_t   s;

    if (uscf->shm_zone == NULL) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST,
                                  "upstream zone is required");
    }

    if (path->len == 0 || (path->len == 1 && path->data[0] == '/')) {
        if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
            return ngx_http_api_stream_write_servers(r, uscf);
        }

        if (r->method == NGX_HTTP_POST) {
            return ngx_http_api_stream_server_post(r, uscf);
        }

        return NGX_HTTP_NOT_ALLOWED;
    }

    if (path->data[0] != '/') {
        return NGX_HTTP_NOT_FOUND;
    }

    s.data = path->data + 1;
    s.len = path->len - 1;

    if (ngx_http_api_parse_id(&s, &id) != NGX_OK) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
        return ngx_http_api_stream_server_get(r, uscf, id);
    }

    if (r->method == NGX_HTTP_PATCH) {
        return ngx_http_api_stream_server_patch(r, uscf, id);
    }

    if (r->method == NGX_HTTP_DELETE) {
        return ngx_http_api_stream_server_delete(r, uscf, id);
    }

    return NGX_HTTP_NOT_ALLOWED;
}


static ngx_int_t
ngx_http_api_stream_server_get(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_uint_t id)
{
    ngx_buf_t                       *b;
    ngx_uint_t                       backup;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers, *peer_peers;

    peers = uscf->peer.data;

    ngx_http_api_stream_peers_rlock(peers);

    peer = ngx_http_api_stream_find_peer(peers, id, &peer_peers, &backup);
    if (peer == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_HTTP_NOT_FOUND;
    }

    b = ngx_http_api_upstream_buffer(r, 1);
    if (b == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_http_api_stream_write_peer(b->last, peer, id, backup);
    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ngx_http_api_stream_peers_unlock(peers);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_stream_server_post(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf)
{
    ngx_buf_t                       *b;
    ngx_int_t                        rc;
    ngx_http_api_peer_conf_t         pcf;

    if (ngx_http_api_parse_json(r, &pcf, 1) != NGX_OK) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST, "invalid json");
    }

    if (pcf.backup_set == 0) {
        pcf.backup = 0;
    }

    if (pcf.drain_set) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST,
                                  "drain is not supported");
    }

    if (ngx_http_api_stream_duplicate(uscf->peer.data, &pcf.server,
                                      pcf.backup))
    {
        return ngx_http_api_error(r, NGX_HTTP_CONFLICT, "duplicate server");
    }

    b = ngx_http_api_upstream_buffer(r, 1);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_api_stream_add_peer(r, uscf, &pcf, b);

    if (rc == NGX_BUSY) {
        return ngx_http_api_error(r, NGX_HTTP_CONFLICT, "duplicate server");
    }

    if (rc != NGX_OK) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST, "invalid server");
    }

    return ngx_http_api_send_status(r, b, NGX_HTTP_CREATED);
}


static ngx_int_t
ngx_http_api_stream_server_patch(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_uint_t id)
{
    ngx_buf_t                       *b;
    ngx_uint_t                       backup;
    ngx_http_api_peer_conf_t         pcf;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers, *peer_peers;

    if (ngx_http_api_parse_json(r, &pcf, 0) != NGX_OK || pcf.server_set
        || pcf.drain_set)
    {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST, "invalid json");
    }

    peers = uscf->peer.data;

    ngx_http_api_stream_peers_wlock(peers);

    peer = ngx_http_api_stream_find_peer(peers, id, &peer_peers, &backup);
    if (peer == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_HTTP_NOT_FOUND;
    }

    if (pcf.backup_set && (ngx_uint_t) pcf.backup != backup) {
        if (ngx_http_api_stream_move_peer(peers, peer_peers, peer, pcf.backup)
            != NGX_OK)
        {
            ngx_http_api_stream_peers_unlock(peers);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        peer_peers = pcf.backup ? peers->next : peers;
        backup = pcf.backup;
    }

    if (pcf.weight_set) {
        peer->weight = pcf.weight;
        peer->effective_weight = pcf.weight;
    }

    if (pcf.max_conns_set) {
        peer->max_conns = pcf.max_conns;
    }

    if (pcf.max_fails_set) {
        peer->max_fails = pcf.max_fails;
    }

    if (pcf.fail_timeout_set) {
        peer->fail_timeout = pcf.fail_timeout;
    }

    if (pcf.slow_start_set) {
        peer->slow_start = pcf.slow_start;
        peer->start_time = ngx_current_msec;
    }

    if (pcf.down_set) {
        if (pcf.down) {
            peer->down |= NGX_STREAM_UPSTREAM_FAILED;
        } else {
            peer->down &= ~NGX_STREAM_UPSTREAM_FAILED;
        }
    }

    if (peers->config) {
        (*peers->config)++;
    }

    ngx_http_api_stream_recount(peers);
    id = ngx_http_api_stream_peer_id(peers, peer);

    b = ngx_http_api_upstream_buffer(r, 1);
    if (b == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_http_api_stream_write_peer(b->last, peer, id, backup);
    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ngx_http_api_stream_peers_unlock(peers);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_stream_server_delete(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_uint_t id)
{
    ngx_buf_t                       *b;
    ngx_uint_t                       backup;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers, *peer_peers;

    peers = uscf->peer.data;

    ngx_http_api_stream_peers_wlock(peers);

    peer = ngx_http_api_stream_find_peer(peers, id, &peer_peers, &backup);
    if (peer == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_HTTP_NOT_FOUND;
    }

    b = ngx_http_api_upstream_buffer(r, 1);
    if (b == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_http_api_stream_write_peer(b->last, peer, id, backup);
    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ngx_http_api_stream_unlink_peer(peer_peers, peer);

    if (peers->config) {
        (*peers->config)++;
    }

    ngx_http_api_stream_recount(peers);

    ngx_stream_upstream_rr_peer_free(peer_peers, peer);

    ngx_http_api_stream_peers_unlock(peers);

    return ngx_http_api_send(r, b);
}


static ngx_stream_upstream_srv_conf_t *
ngx_http_api_stream_find_upstream(ngx_str_t *name)
{
    ngx_uint_t                         i;
    ngx_stream_upstream_srv_conf_t   **uscfp;
    ngx_stream_upstream_main_conf_t   *umcf;

    umcf = ngx_stream_cycle_get_module_main_conf(((ngx_cycle_t *) ngx_cycle),
                                                 ngx_stream_upstream_module);
    if (umcf == NULL) {
        return NULL;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == name->len
            && ngx_memcmp(uscfp[i]->host.data, name->data, name->len) == 0)
        {
            return uscfp[i];
        }
    }

    return NULL;
}


static ngx_stream_upstream_rr_peer_t *
ngx_http_api_stream_find_peer(ngx_stream_upstream_rr_peers_t *peers,
    ngx_uint_t id, ngx_stream_upstream_rr_peers_t **peer_peers,
    ngx_uint_t *backup)
{
    ngx_uint_t                      i;
    ngx_stream_upstream_rr_peer_t  *peer;

    i = 0;

    for (peer = peers->peer; peer; peer = peer->next, i++) {
        if (i == id) {
            *peer_peers = peers;
            *backup = 0;
            return peer;
        }
    }

    if (peers->next == NULL) {
        return NULL;
    }

    for (peer = peers->next->peer; peer; peer = peer->next, i++) {
        if (i == id) {
            *peer_peers = peers->next;
            *backup = 1;
            return peer;
        }
    }

    return NULL;
}


static ngx_uint_t
ngx_http_api_stream_peer_id(ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *peer)
{
    ngx_uint_t                      id;
    ngx_stream_upstream_rr_peer_t  *p;

    id = 0;

    for (p = peers->peer; p; p = p->next, id++) {
        if (p == peer) {
            return id;
        }
    }

    if (peers->next) {
        for (p = peers->next->peer; p; p = p->next, id++) {
            if (p == peer) {
                return id;
            }
        }
    }

    return id;
}


static ngx_int_t
ngx_http_api_stream_add_peer(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf, ngx_http_api_peer_conf_t *pcf,
    ngx_buf_t *b)
{
    ngx_url_t                       u;
    ngx_str_t                       server;
    ngx_uint_t                      down, id;
    ngx_stream_upstream_rr_peer_t  *peer, **peerp;
    ngx_stream_upstream_rr_peers_t *peers, *target;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = pcf->server;

    if (ngx_parse_url(r->pool, &u) != NGX_OK || u.naddrs == 0 || u.no_port) {
        return NGX_ERROR;
    }

    server = pcf->server;
    peers = uscf->peer.data;

    ngx_http_api_stream_peers_wlock(peers);

    if (pcf->backup) {
        if (peers->next == NULL) {
            if (ngx_http_api_stream_alloc_backup(peers) != NGX_OK) {
                ngx_http_api_stream_peers_unlock(peers);
                return NGX_ERROR;
            }

            ngx_stream_upstream_rr_peers_wlock(peers->next);
        }

        target = peers->next;

    } else {
        target = peers;
    }

    if (ngx_http_api_stream_duplicate_locked(target, &server)) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_BUSY;
    }

    peer = ngx_slab_calloc(target->shpool,
                           sizeof(ngx_stream_upstream_rr_peer_t));
    if (peer == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_ERROR;
    }

    peer->sockaddr = ngx_slab_calloc(target->shpool, sizeof(ngx_sockaddr_t));
    peer->name.data = ngx_slab_calloc(target->shpool, NGX_SOCKADDR_STRLEN);
    peer->server.data = ngx_slab_alloc(target->shpool, server.len);

    if (peer->sockaddr == NULL || peer->name.data == NULL
        || peer->server.data == NULL)
    {
        if (peer->sockaddr) {
            ngx_slab_free(target->shpool, peer->sockaddr);
        }

        if (peer->name.data) {
            ngx_slab_free(target->shpool, peer->name.data);
        }

        if (peer->server.data) {
            ngx_slab_free(target->shpool, peer->server.data);
        }

        ngx_slab_free(target->shpool, peer);
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_ERROR;
    }

    ngx_memcpy(peer->sockaddr, u.addrs[0].sockaddr, u.addrs[0].socklen);
    peer->socklen = u.addrs[0].socklen;
    peer->name.len = ngx_sock_ntop(peer->sockaddr, peer->socklen,
                                   peer->name.data, NGX_SOCKADDR_STRLEN, 1);

    ngx_memcpy(peer->server.data, server.data, server.len);
    peer->server.len = server.len;

    peer->weight = pcf->weight_set ? pcf->weight : 1;
    peer->effective_weight = peer->weight;
    peer->current_weight = 0;
    peer->max_conns = pcf->max_conns_set ? pcf->max_conns : 0;
    peer->max_fails = pcf->max_fails_set ? pcf->max_fails : 1;
    peer->fail_timeout = pcf->fail_timeout_set ? pcf->fail_timeout : 10;
    peer->slow_start = pcf->slow_start_set ? pcf->slow_start : 0;
    peer->start_time = ngx_current_msec;

    down = 0;
    if (pcf->down_set && pcf->down) {
        down |= NGX_STREAM_UPSTREAM_FAILED;
    }

    peer->down = down;

    for (peerp = &target->peer; *peerp; peerp = &(*peerp)->next) {
        /* void */
    }

    *peerp = peer;

    if (peers->config) {
        (*peers->config)++;
    }

    ngx_http_api_stream_recount(peers);

    id = (target == peers) ? target->number - 1
                           : peers->number + target->number - 1;

    b->last = ngx_http_api_stream_write_peer(b->last, peer, id, pcf->backup);
    b->last = ngx_cpymem(b->last, CRLF, sizeof(CRLF) - 1);

    ngx_http_api_stream_peers_unlock(peers);

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_stream_alloc_backup(ngx_stream_upstream_rr_peers_t *peers)
{
    ngx_stream_upstream_rr_peers_t  *backup;

    backup = ngx_slab_calloc(peers->shpool,
                             sizeof(ngx_stream_upstream_rr_peers_t));
    if (backup == NULL) {
        return NGX_ERROR;
    }

    backup->shpool = peers->shpool;
    backup->config = peers->config;
    backup->name = peers->name;

    peers->next = backup;

    return NGX_OK;
}


static void
ngx_http_api_stream_recount(ngx_stream_upstream_rr_peers_t *peers)
{
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *p;

    for (p = peers; p; p = p->next) {
        p->number = 0;
        p->tries = 0;
        p->total_weight = 0;
        p->single = 0;

        for (peer = p->peer; peer; peer = peer->next) {
            p->number++;
            p->total_weight += peer->weight;
            p->tries += (peer->down == 0);
        }

        p->weighted = (p->total_weight != p->number);
    }

    if (peers->number == 1
        && (peers->next == NULL || peers->next->number == 0))
    {
        peers->single = 1;
    }
}


static ngx_int_t
ngx_http_api_stream_duplicate(ngx_stream_upstream_rr_peers_t *peers,
    ngx_str_t *server, ngx_uint_t backup)
{
    ngx_int_t                       rc;
    ngx_stream_upstream_rr_peers_t  *target;

    ngx_http_api_stream_peers_rlock(peers);

    target = backup ? peers->next : peers;
    if (target == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return 0;
    }

    rc = ngx_http_api_stream_duplicate_locked(target, server);

    ngx_http_api_stream_peers_unlock(peers);

    return rc;
}


static ngx_int_t
ngx_http_api_stream_duplicate_locked(ngx_stream_upstream_rr_peers_t *peers,
    ngx_str_t *server)
{
    ngx_stream_upstream_rr_peer_t  *peer;

    for (peer = peers->peer; peer; peer = peer->next) {
        if (peer->server.len == server->len
            && ngx_memcmp(peer->server.data, server->data, server->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static void
ngx_http_api_stream_peers_rlock(ngx_stream_upstream_rr_peers_t *peers)
{
    ngx_stream_upstream_rr_peers_rlock(peers);

    if (peers->next) {
        ngx_stream_upstream_rr_peers_rlock(peers->next);
    }
}


static void
ngx_http_api_stream_peers_wlock(ngx_stream_upstream_rr_peers_t *peers)
{
    ngx_stream_upstream_rr_peers_wlock(peers);

    if (peers->next) {
        ngx_stream_upstream_rr_peers_wlock(peers->next);
    }
}


static void
ngx_http_api_stream_peers_unlock(ngx_stream_upstream_rr_peers_t *peers)
{
    if (peers->next) {
        ngx_stream_upstream_rr_peers_unlock(peers->next);
    }

    ngx_stream_upstream_rr_peers_unlock(peers);
}


static u_char *
ngx_http_api_stream_write_peer(u_char *p, ngx_stream_upstream_rr_peer_t *peer,
    ngx_uint_t id, ngx_uint_t backup)
{
    ngx_str_t  *server;

    server = peer->server.len ? &peer->server : &peer->name;

    p = ngx_sprintf(p,
        "{\"id\":%ui,\"server\":\"%V\",\"name\":\"%V\","
        "\"backup\":%s,\"weight\":%i,\"max_conns\":%ui,"
        "\"max_fails\":%ui,\"fail_timeout\":\"%Ts\",",
        id, server, &peer->name, backup ? "true" : "false",
        peer->weight, peer->max_conns, peer->max_fails, peer->fail_timeout);

    p = ngx_cpymem(p, "\"slow_start\":\"", sizeof("\"slow_start\":\"") - 1);
    p = ngx_http_api_time(p, peer->slow_start);

    p = ngx_sprintf(p, "\",\"down\":%s}",
                    (peer->down & NGX_STREAM_UPSTREAM_FAILED)
                    ? "true" : "false");

    return p;
}


static ngx_int_t
ngx_http_api_stream_write_servers(ngx_http_request_t *r,
    ngx_stream_upstream_srv_conf_t *uscf)
{
    ngx_buf_t                       *b;
    ngx_uint_t                       id;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers;

    if (uscf->shm_zone == NULL) {
        return ngx_http_api_error(r, NGX_HTTP_BAD_REQUEST,
                                  "upstream zone is required");
    }

    peers = uscf->peer.data;

    ngx_http_api_stream_peers_rlock(peers);

    b = ngx_http_api_upstream_buffer(r, peers->number
                                        + (peers->next
                                           ? peers->next->number : 0));
    if (b == NULL) {
        ngx_http_api_stream_peers_unlock(peers);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *b->last++ = '[';
    id = 0;

    for (peer = peers->peer; peer; peer = peer->next, id++) {
        if (id != 0) {
            *b->last++ = ',';
        }

        b->last = ngx_http_api_stream_write_peer(b->last, peer, id, 0);
    }

    if (peers->next) {
        for (peer = peers->next->peer; peer; peer = peer->next, id++) {
            if (id != 0) {
                *b->last++ = ',';
            }

            b->last = ngx_http_api_stream_write_peer(b->last, peer, id, 1);
        }
    }

    b->last = ngx_cpymem(b->last, "]" CRLF, sizeof("]" CRLF) - 1);

    ngx_http_api_stream_peers_unlock(peers);

    return ngx_http_api_send(r, b);
}


static ngx_int_t
ngx_http_api_stream_prometheus_peer(ngx_http_api_prometheus_ctx_t *ctx,
    ngx_str_t *upstream,
    ngx_stream_upstream_rr_peer_t *peer)
{
    ngx_str_t  *server;

    server = peer->server.len ? &peer->server : &peer->name;

    if (ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_state"
        "{server=\"%V\",upstream=\"%V\"} %ui" CRLF,
        server, upstream, ngx_http_api_stream_peer_state(peer)) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_active"
        "{server=\"%V\",upstream=\"%V\"} %ui" CRLF,
        server, upstream, peer->conns) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_limit"
        "{server=\"%V\",upstream=\"%V\"} %ui" CRLF,
        server, upstream, peer->max_conns) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_connections"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->connections) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_connect_time"
        "{server=\"%V\",upstream=\"%V\"} %M" CRLF,
        server, upstream, peer->connect_time) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_first_byte_time"
        "{server=\"%V\",upstream=\"%V\"} %M" CRLF,
        server, upstream, peer->first_byte_time) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_response_time"
        "{server=\"%V\",upstream=\"%V\"} %M" CRLF,
        server, upstream, peer->response_time) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_sent"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->sent) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_received"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->received) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_fails"
        "{server=\"%V\",upstream=\"%V\"} %ui" CRLF,
        server, upstream, peer->fails) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_unavail"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->unavail) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_health_checks_checks"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->health_checks) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_health_checks_fails"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->health_fails) != NGX_OK
        || ngx_http_api_prometheus_append(ctx,
        "nginxplus_stream_upstream_server_health_checks_unhealthy"
        "{server=\"%V\",upstream=\"%V\"} %uA" CRLF,
        server, upstream, peer->health_unhealthy) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_api_stream_peer_state(ngx_stream_upstream_rr_peer_t *peer)
{
    if (peer->down & NGX_STREAM_UPSTREAM_FAILED) {
        return 3;
    }

    if (peer->max_fails && peer->fails >= peer->max_fails) {
        return 4;
    }

    if (peer->down & NGX_STREAM_UPSTREAM_HC_DOWN) {
        return 6;
    }

    return 1;
}


static ngx_int_t
ngx_http_api_stream_move_peer(ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peers_t *src, ngx_stream_upstream_rr_peer_t *peer,
    ngx_uint_t backup)
{
    ngx_stream_upstream_rr_peer_t  **peerp;
    ngx_stream_upstream_rr_peers_t  *dst;

    if (backup) {
        if (peers->next == NULL) {
            if (ngx_http_api_stream_alloc_backup(peers) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_stream_upstream_rr_peers_wlock(peers->next);
        }

        dst = peers->next;

    } else {
        dst = peers;
    }

    if (src == dst) {
        return NGX_OK;
    }

    ngx_http_api_stream_unlink_peer(src, peer);

    peer->next = NULL;

    for (peerp = &dst->peer; *peerp; peerp = &(*peerp)->next) {
        /* void */
    }

    *peerp = peer;

    return NGX_OK;
}


static void
ngx_http_api_stream_unlink_peer(ngx_stream_upstream_rr_peers_t *peers,
    ngx_stream_upstream_rr_peer_t *peer)
{
    ngx_stream_upstream_rr_peer_t  **peerp;

    for (peerp = &peers->peer; *peerp; peerp = &(*peerp)->next) {
        if (*peerp == peer) {
            *peerp = peer->next;
            peer->next = NULL;
            return;
        }
    }
}

#endif


static ngx_int_t
ngx_http_api_parse_json(ngx_http_request_t *r, ngx_http_api_peer_conf_t *pcf,
    ngx_uint_t post)
{
    u_char     *p, *last;
    ngx_str_t   key, value, body;
    ngx_int_t   n;

    ngx_memzero(pcf, sizeof(ngx_http_api_peer_conf_t));

    if (ngx_http_api_read_body(r, &body) != NGX_OK) {
        return NGX_ERROR;
    }

    p = body.data;
    last = body.data + body.len;

    ngx_http_api_json_skip_ws(&p, last);

    if (p == last || *p++ != '{') {
        return NGX_ERROR;
    }

    ngx_http_api_json_skip_ws(&p, last);

    if (p < last && *p == '}') {
        p++;
        goto done;
    }

    for ( ;; ) {
        if (ngx_http_api_json_string(&p, last, &key) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_http_api_json_skip_ws(&p, last);

        if (p == last || *p++ != ':') {
            return NGX_ERROR;
        }

        ngx_http_api_json_skip_ws(&p, last);

        if (key.len == sizeof("server") - 1
            && ngx_strncmp(key.data, "server", key.len) == 0)
        {
            if (ngx_http_api_json_string(&p, last, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            pcf->server = value;
            pcf->server_set = 1;

        } else if (key.len == sizeof("weight") - 1
                   && ngx_strncmp(key.data, "weight", key.len) == 0)
        {
            if (ngx_http_api_json_int(&p, last, &n) != NGX_OK || n <= 0) {
                return NGX_ERROR;
            }

            pcf->weight = n;
            pcf->weight_set = 1;

        } else if (key.len == sizeof("max_conns") - 1
                   && ngx_strncmp(key.data, "max_conns", key.len) == 0)
        {
            if (ngx_http_api_json_int(&p, last, &n) != NGX_OK || n < 0) {
                return NGX_ERROR;
            }

            pcf->max_conns = n;
            pcf->max_conns_set = 1;

        } else if (key.len == sizeof("max_fails") - 1
                   && ngx_strncmp(key.data, "max_fails", key.len) == 0)
        {
            if (ngx_http_api_json_int(&p, last, &n) != NGX_OK || n < 0) {
                return NGX_ERROR;
            }

            pcf->max_fails = n;
            pcf->max_fails_set = 1;

        } else if (key.len == sizeof("fail_timeout") - 1
                   && ngx_strncmp(key.data, "fail_timeout", key.len) == 0)
        {
            if (ngx_http_api_json_string(&p, last, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            n = ngx_parse_time(&value, 1);
            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            pcf->fail_timeout = n;
            pcf->fail_timeout_set = 1;

        } else if (key.len == sizeof("slow_start") - 1
                   && ngx_strncmp(key.data, "slow_start", key.len) == 0)
        {
            if (ngx_http_api_json_string(&p, last, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            n = ngx_parse_time(&value, 0);
            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            pcf->slow_start = n;
            pcf->slow_start_set = 1;

        } else if (key.len == sizeof("down") - 1
                   && ngx_strncmp(key.data, "down", key.len) == 0)
        {
            if (ngx_http_api_json_bool(&p, last, &pcf->down) != NGX_OK) {
                return NGX_ERROR;
            }

            pcf->down_set = 1;

        } else if (key.len == sizeof("backup") - 1
                   && ngx_strncmp(key.data, "backup", key.len) == 0)
        {
            if (ngx_http_api_json_bool(&p, last, &pcf->backup) != NGX_OK) {
                return NGX_ERROR;
            }

            pcf->backup_set = 1;

        } else if (key.len == sizeof("drain") - 1
                   && ngx_strncmp(key.data, "drain", key.len) == 0)
        {
            if (ngx_http_api_json_bool(&p, last, &pcf->drain) != NGX_OK) {
                return NGX_ERROR;
            }

            pcf->drain_set = 1;

        } else {
            return NGX_ERROR;
        }

        ngx_http_api_json_skip_ws(&p, last);

        if (p == last) {
            return NGX_ERROR;
        }

        if (*p == '}') {
            p++;
            break;
        }

        if (*p++ != ',') {
            return NGX_ERROR;
        }

        ngx_http_api_json_skip_ws(&p, last);
    }

done:

    ngx_http_api_json_skip_ws(&p, last);

    if (p != last) {
        return NGX_ERROR;
    }

    if (post && !pcf->server_set) {
        return NGX_ERROR;
    }

    if (!post && !pcf->server_set && !pcf->weight_set
        && !pcf->max_conns_set && !pcf->max_fails_set
        && !pcf->fail_timeout_set && !pcf->slow_start_set
        && !pcf->down_set && !pcf->backup_set && !pcf->drain_set)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_json_string(u_char **pos, u_char *last, ngx_str_t *value)
{
    u_char  *p;

    p = *pos;

    if (p == last || *p++ != '"') {
        return NGX_ERROR;
    }

    value->data = p;

    while (p < last) {
        if (*p == '"') {
            value->len = p - value->data;
            *pos = p + 1;
            return NGX_OK;
        }

        if (*p < 0x20 || *p == '\\') {
            return NGX_ERROR;
        }

        p++;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_api_json_bool(u_char **pos, u_char *last, ngx_flag_t *value)
{
    u_char  *p;

    p = *pos;

    if ((size_t) (last - p) >= sizeof("true") - 1
        && ngx_strncmp(p, "true", sizeof("true") - 1) == 0)
    {
        *value = 1;
        *pos = p + sizeof("true") - 1;
        return NGX_OK;
    }

    if ((size_t) (last - p) >= sizeof("false") - 1
        && ngx_strncmp(p, "false", sizeof("false") - 1) == 0)
    {
        *value = 0;
        *pos = p + sizeof("false") - 1;
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_api_json_int(u_char **pos, u_char *last, ngx_int_t *value)
{
    u_char     *p, *start;
    ngx_int_t  n;

    p = *pos;
    start = p;

    while (p < last && *p >= '0' && *p <= '9') {
        p++;
    }

    if (p == start) {
        return NGX_ERROR;
    }

    n = ngx_atoi(start, p - start);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    *value = n;
    *pos = p;

    return NGX_OK;
}


static void
ngx_http_api_json_skip_ws(u_char **pos, u_char *last)
{
    u_char  *p;

    p = *pos;

    while (p < last) {
        switch (*p) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            p++;
            continue;
        }

        break;
    }

    *pos = p;
}


static ngx_int_t
ngx_http_api_parse_id(ngx_str_t *path, ngx_uint_t *id)
{
    ngx_int_t  n;

    if (path->len == 0) {
        return NGX_ERROR;
    }

    n = ngx_atoi(path->data, path->len);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    *id = n;

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_error(ngx_http_request_t *r, ngx_uint_t status, const char *text)
{
    ngx_buf_t  *b;

    b = ngx_create_temp_buf(r->pool, 128);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_sprintf(b->last, "{\"error\":\"%s\"}" CRLF, text);

    return ngx_http_api_send_status(r, b, status);
}


static ngx_buf_t *
ngx_http_api_upstream_buffer(ngx_http_request_t *r, ngx_uint_t peers)
{
    size_t  size;

    size = 8192 + peers * 1024;

    return ngx_create_temp_buf(r->pool, size);
}


static ngx_int_t
ngx_http_api_valid_label(ngx_str_t *name)
{
    size_t  i;

    if (name->len == 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < name->len; i++) {
        if (name->data[i] < 0x20
            || name->data[i] == '"'
            || name->data[i] == '\\')
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static u_char *
ngx_http_api_time(u_char *p, ngx_msec_t msec)
{
    if (msec % 1000 == 0) {
        return ngx_sprintf(p, "%Ms", msec / 1000);
    }

    return ngx_sprintf(p, "%Mms", msec);
}
