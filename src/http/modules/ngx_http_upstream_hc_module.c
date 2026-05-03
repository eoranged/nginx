
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>
#include <ngx_http_upstream_round_robin.h>


typedef struct {
    ngx_str_t                       name;
    ngx_uint_t                      status;
    ngx_str_t                       header_name;
    ngx_str_t                       header_value;
    ngx_str_t                       body;
} ngx_http_upstream_hc_match_t;


typedef struct {
    ngx_http_upstream_srv_conf_t   *uscf;
    ngx_http_upstream_hc_match_t   *match;
    ngx_msec_t                      interval;
    ngx_msec_t                      jitter;
    ngx_msec_t                      timeout;
    ngx_uint_t                      fails;
    ngx_uint_t                      passes;
    ngx_str_t                       uri;
    in_port_t                       port;
    ngx_uint_t                      mandatory;
    ngx_uint_t                      persistent;
} ngx_http_upstream_hc_conf_t;


typedef struct {
    ngx_array_t                    *matches;
    ngx_array_t                    *checks;
    ngx_array_t                    *peers;
} ngx_http_upstream_hc_main_conf_t;


typedef struct {
    ngx_event_t                     event;
    ngx_peer_connection_t           pc;
    ngx_sockaddr_t                  sockaddr;
    ngx_str_t                       name;
    u_char                          name_data[NGX_SOCKADDR_STRLEN];
    u_char                          request[512];
    u_char                          buffer[4096];
    ngx_http_upstream_hc_conf_t    *conf;
    ngx_http_upstream_rr_peers_t   *peers;
    ngx_http_upstream_rr_peer_t    *peer;
    size_t                          request_len;
    size_t                          sent;
    size_t                          received;
    ngx_uint_t                      fails;
    ngx_uint_t                      passes;
    ngx_uint_t                      state;
    unsigned                        referenced:1;
    unsigned                        done:1;
} ngx_http_upstream_hc_peer_t;


#define NGX_HTTP_UPSTREAM_HC_CONNECT  0
#define NGX_HTTP_UPSTREAM_HC_SEND     1
#define NGX_HTTP_UPSTREAM_HC_RECV     2


static void *ngx_http_upstream_hc_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_hc_match_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_hc_match(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);
static char *ngx_http_upstream_hc(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_upstream_hc_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_hc_init_worker(ngx_cycle_t *cycle);
static void ngx_http_upstream_hc_exit_worker(ngx_cycle_t *cycle);
static void ngx_http_upstream_hc_clear_stale(ngx_cycle_t *cycle,
    ngx_http_upstream_hc_main_conf_t *hmcf);
static ngx_http_upstream_hc_conf_t *ngx_http_upstream_hc_find_check(
    ngx_http_upstream_hc_main_conf_t *hmcf,
    ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_http_upstream_hc_has_resolve(
    ngx_http_upstream_srv_conf_t *uscf);
static ngx_uint_t ngx_http_upstream_hc_active_peers(
    ngx_http_upstream_rr_peers_t *peers);
static void ngx_http_upstream_hc_clear_peers(
    ngx_http_upstream_rr_peers_t *peers);
static ngx_int_t ngx_http_upstream_hc_start_peers(ngx_cycle_t *cycle,
    ngx_http_upstream_hc_main_conf_t *hmcf, ngx_http_upstream_hc_conf_t *hc,
    ngx_http_upstream_rr_peers_t *peers);
static void ngx_http_upstream_hc_timer(ngx_event_t *event);
static ngx_int_t ngx_http_upstream_hc_start(ngx_http_upstream_hc_peer_t *hp);
static void ngx_http_upstream_hc_event_handler(ngx_event_t *ev);
static void ngx_http_upstream_hc_send_handler(ngx_http_upstream_hc_peer_t *hp);
static void ngx_http_upstream_hc_recv_handler(ngx_http_upstream_hc_peer_t *hp);
static ngx_int_t ngx_http_upstream_hc_test_connect(ngx_connection_t *c);
static void ngx_http_upstream_hc_finalize(ngx_http_upstream_hc_peer_t *hp,
    ngx_int_t ok);
static void ngx_http_upstream_hc_update(ngx_http_upstream_hc_peer_t *hp,
    ngx_int_t ok);
static ngx_msec_t ngx_http_upstream_hc_delay(ngx_http_upstream_hc_conf_t *hc);
static ngx_int_t ngx_http_upstream_hc_peer_gone(
    ngx_http_upstream_hc_peer_t *hp);
static void ngx_http_upstream_hc_unlink_peer(ngx_http_upstream_hc_peer_t *hp);
static ngx_int_t ngx_http_upstream_hc_match_response(
    ngx_http_upstream_hc_match_t *match, u_char *buf, size_t len);
static ngx_int_t ngx_http_upstream_hc_match_header(
    ngx_http_upstream_hc_match_t *match, u_char *buf, size_t len,
    u_char *header_end);
static u_char *ngx_http_upstream_hc_find(u_char *buf, size_t len,
    u_char *needle, size_t nlen);
static ngx_http_upstream_hc_match_t *ngx_http_upstream_hc_find_match(
    ngx_http_upstream_hc_main_conf_t *hmcf, ngx_str_t *name);


static ngx_str_t  ngx_http_upstream_hc_default_uri = ngx_string("/");


static ngx_command_t  ngx_http_upstream_hc_commands[] = {

    { ngx_string("match"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_upstream_hc_match_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("health_check"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_hc,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_hc_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_upstream_hc_init,             /* postconfiguration */

    ngx_http_upstream_hc_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_hc_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_hc_module_ctx,      /* module context */
    ngx_http_upstream_hc_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_upstream_hc_init_worker,      /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_upstream_hc_exit_worker,      /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_upstream_hc_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_hc_main_conf_t  *hmcf;

    hmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_hc_main_conf_t));
    if (hmcf == NULL) {
        return NULL;
    }

    hmcf->matches = ngx_array_create(cf->pool, 4,
                                     sizeof(ngx_http_upstream_hc_match_t));
    if (hmcf->matches == NULL) {
        return NULL;
    }

    hmcf->checks = ngx_array_create(cf->pool, 4,
                                    sizeof(ngx_http_upstream_hc_conf_t));
    if (hmcf->checks == NULL) {
        return NULL;
    }

    hmcf->peers = ngx_array_create(cf->pool, 4,
                                   sizeof(ngx_http_upstream_hc_peer_t *));
    if (hmcf->peers == NULL) {
        return NULL;
    }

    return hmcf;
}


static char *
ngx_http_upstream_hc_match_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char                             *rv;
    ngx_str_t                        *value;
    ngx_conf_t                        save;
    ngx_http_upstream_hc_match_t     *match;
    ngx_http_upstream_hc_main_conf_t *hmcf;

    hmcf = conf;
    value = cf->args->elts;

    if (ngx_http_upstream_hc_find_match(hmcf, &value[1]) != NULL) {
        return "is duplicate";
    }

    match = ngx_array_push(hmcf->matches);
    if (match == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(match, sizeof(ngx_http_upstream_hc_match_t));
    match->name = value[1];
    match->status = NGX_CONF_UNSET_UINT;

    save = *cf;
    cf->handler = ngx_http_upstream_hc_match;
    cf->handler_conf = match;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
ngx_http_upstream_hc_match(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_int_t                     n;
    ngx_str_t                    *value;
    ngx_http_upstream_hc_match_t *match = conf;

    value = cf->args->elts;

    if (cf->args->nelts == 2
        && value[0].len == sizeof("status") - 1
        && ngx_strncmp(value[0].data, "status", sizeof("status") - 1) == 0)
    {
        n = ngx_atoi(value[1].data, value[1].len);
        if (n < 100 || n > 599) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid status \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        match->status = n;
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 4
        && value[0].len == sizeof("header") - 1
        && ngx_strncmp(value[0].data, "header", sizeof("header") - 1) == 0
        && value[2].len == 1
        && value[2].data[0] == '=')
    {
        match->header_name = value[1];
        match->header_value = value[3];
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 3
        && value[0].len == sizeof("body") - 1
        && ngx_strncmp(value[0].data, "body", sizeof("body") - 1) == 0
        && value[1].len == 1
        && value[1].data[0] == '~')
    {
        match->body = value[2];
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid match directive \"%V\"", &value[0]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_upstream_hc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                         n;
    ngx_str_t                        *value, s;
    ngx_uint_t                        i;
    ngx_http_proxy_loc_conf_t        *plcf;
    ngx_http_upstream_hc_conf_t      *hc, *checks;
    ngx_http_upstream_hc_main_conf_t *hmcf;

    plcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);

    if (plcf->proxy_lengths || plcf->upstream.upstream == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"health_check\" requires a static "
                           "\"proxy_pass\" configured before it");
        return NGX_CONF_ERROR;
    }

    hmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_upstream_hc_module);

    if (ngx_http_upstream_hc_has_resolve(plcf->upstream.upstream)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"health_check\" does not support upstream "
                           "servers with \"resolve\"");
        return NGX_CONF_ERROR;
    }

    checks = hmcf->checks->elts;
    for (i = 0; i < hmcf->checks->nelts; i++) {
        if (checks[i].uscf == plcf->upstream.upstream) {
            return "is duplicate";
        }
    }

    hc = ngx_array_push(hmcf->checks);
    if (hc == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(hc, sizeof(ngx_http_upstream_hc_conf_t));
    hc->uscf = plcf->upstream.upstream;
    hc->interval = 5000;
    hc->timeout = 5000;
    hc->fails = 1;
    hc->passes = 1;
    hc->uri = ngx_http_upstream_hc_default_uri;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == sizeof("mandatory") - 1
            && ngx_strncmp(value[i].data, "mandatory",
                           sizeof("mandatory") - 1)
               == 0)
        {
            hc->mandatory = 1;
            continue;
        }

        if (value[i].len == sizeof("persistent") - 1
            && ngx_strncmp(value[i].data, "persistent",
                           sizeof("persistent") - 1)
               == 0)
        {
            hc->persistent = 1;
            continue;
        }

        if (value[i].len > sizeof("interval=") - 1
            && ngx_strncmp(value[i].data, "interval=",
                           sizeof("interval=") - 1)
               == 0)
        {
            s.len = value[i].len - (sizeof("interval=") - 1);
            s.data = value[i].data + sizeof("interval=") - 1;
            n = ngx_parse_time(&s, 0);

            if (n <= 0) {
                goto invalid;
            }

            hc->interval = n;
            continue;
        }

        if (value[i].len > sizeof("jitter=") - 1
            && ngx_strncmp(value[i].data, "jitter=",
                           sizeof("jitter=") - 1)
               == 0)
        {
            s.len = value[i].len - (sizeof("jitter=") - 1);
            s.data = value[i].data + sizeof("jitter=") - 1;
            n = ngx_parse_time(&s, 0);

            if (n < 0) {
                goto invalid;
            }

            hc->jitter = n;
            continue;
        }

        if (value[i].len > sizeof("fails=") - 1
            && ngx_strncmp(value[i].data, "fails=", sizeof("fails=") - 1)
               == 0)
        {
            s.len = value[i].len - (sizeof("fails=") - 1);
            s.data = value[i].data + sizeof("fails=") - 1;
            n = ngx_atoi(s.data, s.len);

            if (n <= 0) {
                goto invalid;
            }

            hc->fails = n;
            continue;
        }

        if (value[i].len > sizeof("passes=") - 1
            && ngx_strncmp(value[i].data, "passes=", sizeof("passes=") - 1)
               == 0)
        {
            s.len = value[i].len - (sizeof("passes=") - 1);
            s.data = value[i].data + sizeof("passes=") - 1;
            n = ngx_atoi(s.data, s.len);

            if (n <= 0) {
                goto invalid;
            }

            hc->passes = n;
            continue;
        }

        if (value[i].len > sizeof("uri=") - 1
            && ngx_strncmp(value[i].data, "uri=", sizeof("uri=") - 1) == 0)
        {
            hc->uri.len = value[i].len - (sizeof("uri=") - 1);
            hc->uri.data = value[i].data + sizeof("uri=") - 1;
            continue;
        }

        if (value[i].len > sizeof("match=") - 1
            && ngx_strncmp(value[i].data, "match=", sizeof("match=") - 1)
               == 0)
        {
            s.len = value[i].len - (sizeof("match=") - 1);
            s.data = value[i].data + sizeof("match=") - 1;
            hc->match = ngx_http_upstream_hc_find_match(hmcf, &s);

            if (hc->match == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "unknown match \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (value[i].len > sizeof("port=") - 1
            && ngx_strncmp(value[i].data, "port=", sizeof("port=") - 1) == 0)
        {
            s.len = value[i].len - (sizeof("port=") - 1);
            s.data = value[i].data + sizeof("port=") - 1;
            n = ngx_atoi(s.data, s.len);

            if (n <= 0 || n > 65535) {
                goto invalid;
            }

            hc->port = (in_port_t) n;
            continue;
        }

        goto invalid;
    }

    if (hc->persistent && !hc->mandatory) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"persistent\" requires \"mandatory\"");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid health_check parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_upstream_hc_init(ngx_conf_t *cf)
{
    ngx_uint_t                         i;
    ngx_http_upstream_hc_conf_t       *hc;
    ngx_http_upstream_hc_main_conf_t  *hmcf;

    hmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_upstream_hc_module);

    if (hmcf == NULL || hmcf->checks == NULL) {
        return NGX_OK;
    }

    hc = hmcf->checks->elts;

    for (i = 0; i < hmcf->checks->nelts; i++) {
        if (ngx_http_upstream_hc_has_resolve(hc[i].uscf)) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "\"health_check\" does not support upstream "
                          "\"%V\" with \"resolve\"", &hc[i].uscf->host);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_hc_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                         i;
    ngx_http_upstream_hc_conf_t       *hc;
    ngx_http_upstream_hc_main_conf_t  *hmcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    hmcf = ngx_http_cycle_get_module_main_conf(cycle,
                                               ngx_http_upstream_hc_module);

    if (hmcf == NULL || hmcf->checks == NULL) {
        return NGX_OK;
    }

    hc = hmcf->checks->elts;

    ngx_http_upstream_hc_clear_stale(cycle, hmcf);

    for (i = 0; i < hmcf->checks->nelts; i++) {
        if (hc[i].uscf->peer.data == NULL) {
            continue;
        }

        if (ngx_http_upstream_hc_start_peers(cycle, hmcf, &hc[i],
                                             hc[i].uscf->peer.data)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_http_upstream_hc_exit_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                         i;
    ngx_http_upstream_hc_peer_t      **hpp;
    ngx_http_upstream_hc_main_conf_t  *hmcf;

    hmcf = ngx_http_cycle_get_module_main_conf(cycle,
                                               ngx_http_upstream_hc_module);

    if (hmcf == NULL || hmcf->peers == NULL) {
        return;
    }

    hpp = hmcf->peers->elts;

    for (i = 0; i < hmcf->peers->nelts; i++) {
        ngx_http_upstream_hc_unlink_peer(hpp[i]);
    }
}


static void
ngx_http_upstream_hc_clear_stale(ngx_cycle_t *cycle,
    ngx_http_upstream_hc_main_conf_t *hmcf)
{
    ngx_uint_t                       i;
    ngx_http_upstream_hc_conf_t     *hc;
    ngx_http_upstream_srv_conf_t    *uscf, **uscfp;
    ngx_http_upstream_main_conf_t   *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(cycle,
                                               ngx_http_upstream_module);
    if (umcf == NULL) {
        return;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->peer.data == NULL) {
            continue;
        }

        hc = ngx_http_upstream_hc_find_check(hmcf, uscf);

#if (NGX_HTTP_UPSTREAM_ZONE)
        if (hc && hc->persistent && uscf->shm_zone
            && (uscf->shm_zone->shm.exists
                || ngx_http_upstream_hc_active_peers(uscf->peer.data)))
        {
            continue;
        }
#endif

        ngx_http_upstream_hc_clear_peers(uscf->peer.data);
    }
}


static ngx_http_upstream_hc_conf_t *
ngx_http_upstream_hc_find_check(ngx_http_upstream_hc_main_conf_t *hmcf,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_uint_t                    i;
    ngx_http_upstream_hc_conf_t  *hc;

    hc = hmcf->checks->elts;

    for (i = 0; i < hmcf->checks->nelts; i++) {
        if (hc[i].uscf == uscf) {
            return &hc[i];
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_upstream_hc_has_resolve(ngx_http_upstream_srv_conf_t *uscf)
{
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_uint_t                    i;
    ngx_http_upstream_server_t   *us;

    if (uscf->servers == NULL) {
        return 0;
    }

    us = uscf->servers->elts;

    for (i = 0; i < uscf->servers->nelts; i++) {
        if (us[i].host.len) {
            return 1;
        }
    }
#endif

    return 0;
}


static ngx_uint_t
ngx_http_upstream_hc_active_peers(ngx_http_upstream_rr_peers_t *peers)
{
#if (NGX_HTTP_UPSTREAM_ZONE)
    do {
        if (peers->shpool && peers->hc_active) {
            return 1;
        }

        peers = peers->next;

    } while (peers);
#endif

    return 0;
}


static void
ngx_http_upstream_hc_clear_peers(ngx_http_upstream_rr_peers_t *peers)
{
    ngx_http_upstream_rr_peer_t  *peer;

    do {
        ngx_http_upstream_rr_peers_wlock(peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
        if (peers->shpool) {
            peers->hc_active = 0;
        }
#endif

        for (peer = peers->peer; peer; peer = peer->next) {
            peer->down &= ~NGX_HTTP_UPSTREAM_HC_DOWN;
        }

        ngx_http_upstream_rr_peers_unlock(peers);

        peers = peers->next;

    } while (peers);
}


static ngx_int_t
ngx_http_upstream_hc_start_peers(ngx_cycle_t *cycle,
    ngx_http_upstream_hc_main_conf_t *hmcf, ngx_http_upstream_hc_conf_t *hc,
    ngx_http_upstream_rr_peers_t *peers)
{
    ngx_uint_t                    persistent;
    ngx_http_upstream_hc_peer_t **hpp;
    ngx_http_upstream_hc_peer_t  *hp;
    ngx_http_upstream_rr_peer_t  *peer;

    do {
        persistent = 0;

        ngx_http_upstream_rr_peers_wlock(peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
        if (peers->shpool) {
            persistent = (hc->persistent && peers->hc_active);
            peers->hc_active = 1;
        }
#endif

        for (peer = peers->peer; peer; peer = peer->next) {

            if (hc->mandatory && !persistent) {
                peer->down |= NGX_HTTP_UPSTREAM_HC_DOWN;
            }

            hp = ngx_pcalloc(cycle->pool, sizeof(ngx_http_upstream_hc_peer_t));
            if (hp == NULL) {
                ngx_http_upstream_rr_peers_unlock(peers);
                return NGX_ERROR;
            }

            hp->conf = hc;
            hp->peers = peers;
            hp->peer = peer;

            hpp = ngx_array_push(hmcf->peers);
            if (hpp == NULL) {
                ngx_http_upstream_rr_peers_unlock(peers);
                return NGX_ERROR;
            }

            *hpp = hp;

            hp->referenced = 1;
            ngx_http_upstream_rr_peer_ref(peers, peer);

            hp->event.data = hp;
            hp->event.handler = ngx_http_upstream_hc_timer;
            hp->event.log = cycle->log;
            hp->event.cancelable = 1;

            ngx_add_timer(&hp->event, 1);
        }

        ngx_http_upstream_rr_peers_unlock(peers);

        peers = peers->next;

    } while (peers);

    return NGX_OK;
}


static void
ngx_http_upstream_hc_timer(ngx_event_t *event)
{
    ngx_http_upstream_hc_peer_t  *hp;

    if (ngx_terminate || ngx_quit || ngx_exiting) {
        return;
    }

    hp = event->data;

    if (hp->done || ngx_http_upstream_hc_peer_gone(hp)) {
        return;
    }

    if (ngx_http_upstream_hc_start(hp) != NGX_OK) {
        ngx_http_upstream_hc_finalize(hp, NGX_ERROR);
    }
}


static ngx_int_t
ngx_http_upstream_hc_start(ngx_http_upstream_hc_peer_t *hp)
{
    u_char                       *p;
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_http_upstream_hc_conf_t  *hc;

    hc = hp->conf;

    ngx_memzero(&hp->pc, sizeof(ngx_peer_connection_t));
    ngx_memcpy(&hp->sockaddr, hp->peer->sockaddr, hp->peer->socklen);

    if (hc->port) {
        ngx_inet_set_port((struct sockaddr *) &hp->sockaddr, hc->port);
    }

    hp->name.data = hp->name_data;
    hp->name.len = ngx_sock_ntop((struct sockaddr *) &hp->sockaddr,
                                 hp->peer->socklen, hp->name.data,
                                 NGX_SOCKADDR_STRLEN, 1);

    p = ngx_slprintf(hp->request, hp->request + sizeof(hp->request),
                     "GET %V HTTP/1.0" CRLF
                     "Host: %V" CRLF
                     "Connection: close" CRLF CRLF,
                     &hc->uri, hp->peers->name);

    hp->request_len = p - hp->request;
    hp->sent = 0;
    hp->received = 0;
    hp->state = NGX_HTTP_UPSTREAM_HC_CONNECT;

    hp->pc.sockaddr = (struct sockaddr *) &hp->sockaddr;
    hp->pc.socklen = hp->peer->socklen;
    hp->pc.name = &hp->name;
    hp->pc.get = ngx_event_get_peer;
    hp->pc.log = hp->event.log;
    hp->pc.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&hp->pc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        return NGX_ERROR;
    }

    c = hp->pc.connection;

    c->data = hp;
    c->read->data = hp;
    c->write->data = hp;
    c->read->handler = ngx_http_upstream_hc_event_handler;
    c->write->handler = ngx_http_upstream_hc_event_handler;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, hc->timeout);
        return NGX_OK;
    }

    hp->state = NGX_HTTP_UPSTREAM_HC_SEND;
    ngx_http_upstream_hc_send_handler(hp);

    return NGX_OK;
}


static void
ngx_http_upstream_hc_event_handler(ngx_event_t *ev)
{
    ngx_http_upstream_hc_peer_t  *hp;

    hp = ev->data;

    if (hp->done) {
        return;
    }

    if (ngx_terminate || ngx_quit || ngx_exiting) {
        ngx_http_upstream_hc_unlink_peer(hp);
        return;
    }

    if (ev->timedout) {
        ngx_http_upstream_hc_finalize(hp, NGX_ERROR);
        return;
    }

    switch (hp->state) {
    case NGX_HTTP_UPSTREAM_HC_CONNECT:
        if (ev->timer_set) {
            ngx_del_timer(ev);
        }

        if (ngx_http_upstream_hc_test_connect(hp->pc.connection) != NGX_OK) {
            ngx_http_upstream_hc_finalize(hp, NGX_ERROR);
            return;
        }

        hp->state = NGX_HTTP_UPSTREAM_HC_SEND;
        ngx_http_upstream_hc_send_handler(hp);
        return;

    case NGX_HTTP_UPSTREAM_HC_SEND:
        ngx_http_upstream_hc_send_handler(hp);
        return;

    default:
        ngx_http_upstream_hc_recv_handler(hp);
    }
}


static void
ngx_http_upstream_hc_send_handler(ngx_http_upstream_hc_peer_t *hp)
{
    ssize_t            n;
    ngx_connection_t  *c;

    c = hp->pc.connection;

    while (hp->sent < hp->request_len) {
        n = c->send(c, hp->request + hp->sent, hp->request_len - hp->sent);

        if (n == NGX_ERROR) {
            ngx_http_upstream_hc_finalize(hp, NGX_ERROR);
            return;
        }

        if (n == 0) {
            ngx_http_upstream_hc_finalize(hp, NGX_ERROR);
            return;
        }

        if (n == NGX_AGAIN) {
            if (!c->write->timer_set) {
                ngx_add_timer(c->write, hp->conf->timeout);
            }

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_http_upstream_hc_finalize(hp, NGX_ERROR);
            }

            return;
        }

        hp->sent += n;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    hp->state = NGX_HTTP_UPSTREAM_HC_RECV;

    if (!c->read->timer_set) {
        ngx_add_timer(c->read, hp->conf->timeout);
    }

    ngx_http_upstream_hc_recv_handler(hp);
}


static void
ngx_http_upstream_hc_recv_handler(ngx_http_upstream_hc_peer_t *hp)
{
    u_char            *p;
    ssize_t            n;
    ngx_connection_t  *c;

    c = hp->pc.connection;

    for ( ;; ) {
        n = c->recv(c, hp->buffer + hp->received,
                    sizeof(hp->buffer) - hp->received);

        if (n == NGX_ERROR || n == 0) {
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            ngx_http_upstream_hc_finalize(hp,
                hp->received ? ngx_http_upstream_hc_match_response(
                                   hp->conf->match, hp->buffer, hp->received)
                             : NGX_ERROR);
            return;
        }

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_http_upstream_hc_finalize(hp, NGX_ERROR);
            }

            return;
        }

        hp->received += n;

        if (hp->received == sizeof(hp->buffer)) {
            ngx_http_upstream_hc_finalize(hp,
                ngx_http_upstream_hc_match_response(hp->conf->match,
                                                    hp->buffer, hp->received));
            return;
        }

        p = ngx_http_upstream_hc_find(hp->buffer, hp->received,
                                      (u_char *) CRLF CRLF, 4);
        if (p == NULL) {
            p = ngx_http_upstream_hc_find(hp->buffer, hp->received,
                                          (u_char *) "\n\n", 2);
        }

        if (p == NULL) {
            continue;
        }

        if (hp->conf->match == NULL || hp->conf->match->body.len == 0) {
            ngx_http_upstream_hc_finalize(hp,
                ngx_http_upstream_hc_match_response(hp->conf->match,
                                                    hp->buffer, hp->received));
            return;
        }

        if (ngx_http_upstream_hc_find(p, hp->buffer + hp->received - p,
                                      hp->conf->match->body.data,
                                      hp->conf->match->body.len)
            != NULL)
        {
            ngx_http_upstream_hc_finalize(hp,
                ngx_http_upstream_hc_match_response(hp->conf->match,
                                                    hp->buffer, hp->received));
            return;
        }
    }
}


static ngx_int_t
ngx_http_upstream_hc_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            err = c->write->pending_eof ? c->write->kq_errno
                                        : c->read->kq_errno;

            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_http_upstream_hc_finalize(ngx_http_upstream_hc_peer_t *hp, ngx_int_t ok)
{
    ngx_connection_t  *c;

    if (hp->done) {
        return;
    }

    c = hp->pc.connection;

    if (c) {
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_close_connection(c);
        hp->pc.connection = NULL;
    }

    if (ngx_http_upstream_hc_peer_gone(hp)) {
        return;
    }

    if (ngx_terminate || ngx_quit || ngx_exiting) {
        ngx_http_upstream_hc_unlink_peer(hp);
        return;
    }

    ngx_http_upstream_hc_update(hp, ok);

    ngx_add_timer(&hp->event, hp->conf->interval
                              + ngx_http_upstream_hc_delay(hp->conf));
}


static void
ngx_http_upstream_hc_update(ngx_http_upstream_hc_peer_t *hp, ngx_int_t ok)
{
    ngx_http_upstream_rr_peer_t  *peer;

    peer = hp->peer;

    ngx_http_upstream_rr_peers_wlock(hp->peers);

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (hp->peers->shpool && !hp->peers->hc_active) {
        ngx_http_upstream_rr_peers_unlock(hp->peers);
        return;
    }
#endif

    if (ok == NGX_OK) {
        peer->health_checks++;
        peer->health_last_passed = 1;
        hp->fails = 0;

        if (hp->passes < hp->conf->passes) {
            hp->passes++;
        }

        if (hp->passes >= hp->conf->passes) {
            peer->down &= ~NGX_HTTP_UPSTREAM_HC_DOWN;
        }

    } else {
        peer->health_checks++;
        peer->health_fails++;
        peer->health_last_passed = 0;
        hp->passes = 0;

        if (hp->fails < hp->conf->fails) {
            hp->fails++;
        }

        if (hp->fails >= hp->conf->fails) {
            if (!(peer->down & NGX_HTTP_UPSTREAM_HC_DOWN)) {
                peer->health_unhealthy++;
            }

            peer->down |= NGX_HTTP_UPSTREAM_HC_DOWN;
        }
    }

    ngx_http_upstream_rr_peers_unlock(hp->peers);
}


static ngx_msec_t
ngx_http_upstream_hc_delay(ngx_http_upstream_hc_conf_t *hc)
{
    if (hc->jitter == 0) {
        return 0;
    }

    return (ngx_msec_t) (ngx_random() % hc->jitter);
}


static ngx_int_t
ngx_http_upstream_hc_peer_gone(ngx_http_upstream_hc_peer_t *hp)
{
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_http_upstream_rr_peer_t  *peer;

    if (hp->done) {
        return 1;
    }

    peer = hp->peer;

    ngx_http_upstream_rr_peers_rlock(hp->peers);
    ngx_http_upstream_rr_peer_lock(hp->peers, peer);

    if (peer->zombie) {
        hp->done = 1;
        hp->referenced = 0;

        if (ngx_http_upstream_rr_peer_unref(hp->peers, peer) == NGX_OK) {
            ngx_http_upstream_rr_peer_unlock(hp->peers, peer);
        }

        ngx_http_upstream_rr_peers_unlock(hp->peers);

        return 1;
    }

    ngx_http_upstream_rr_peer_unlock(hp->peers, peer);
    ngx_http_upstream_rr_peers_unlock(hp->peers);
#endif

    return 0;
}


static void
ngx_http_upstream_hc_unlink_peer(ngx_http_upstream_hc_peer_t *hp)
{
    ngx_connection_t  *c;

    if (hp == NULL || hp->done) {
        return;
    }

    if (hp->event.timer_set) {
        ngx_del_timer(&hp->event);
    }

    c = hp->pc.connection;

    if (c) {
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_close_connection(c);
        hp->pc.connection = NULL;
    }

    if (!hp->referenced) {
        hp->done = 1;
        return;
    }

    hp->referenced = 0;
    hp->done = 1;

    ngx_http_upstream_rr_peers_rlock(hp->peers);
    ngx_http_upstream_rr_peer_lock(hp->peers, hp->peer);

    if (ngx_http_upstream_rr_peer_unref(hp->peers, hp->peer) == NGX_OK) {
        ngx_http_upstream_rr_peer_unlock(hp->peers, hp->peer);
    }

    ngx_http_upstream_rr_peers_unlock(hp->peers);
}


static ngx_int_t
ngx_http_upstream_hc_match_response(ngx_http_upstream_hc_match_t *match,
    u_char *buf, size_t len)
{
    ngx_int_t   status;
    u_char     *p, *last, *header_end;

    last = buf + len;

    p = ngx_strlchr(buf, last, ' ');
    if (p == NULL || p + 4 > last) {
        return NGX_ERROR;
    }

    status = ngx_atoi(p + 1, 3);
    if (status == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (match == NULL || match->status == NGX_CONF_UNSET_UINT) {
        if (status < 200 || status > 399) {
            return NGX_ERROR;
        }

    } else if ((ngx_uint_t) status != match->status) {
        return NGX_ERROR;
    }

    if (match == NULL) {
        return NGX_OK;
    }

    header_end = ngx_http_upstream_hc_find(buf, len, (u_char *) CRLF CRLF, 4);
    if (header_end == NULL) {
        header_end = ngx_http_upstream_hc_find(buf, len, (u_char *) "\n\n", 2);
    }

    if (match->header_name.len
        && (header_end == NULL
            || ngx_http_upstream_hc_match_header(match, buf, len, header_end)
               != NGX_OK))
    {
        return NGX_ERROR;
    }

    if (match->body.len) {
        if (header_end == NULL) {
            header_end = buf;
        }

        if (ngx_http_upstream_hc_find(header_end, last - header_end,
                                      match->body.data, match->body.len)
            == NULL)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_hc_match_header(ngx_http_upstream_hc_match_t *match,
    u_char *buf, size_t len, u_char *header_end)
{
    u_char  *line, *next, *colon, *value, *line_end;

    line = ngx_strlchr(buf, buf + len, '\n');

    if (line == NULL) {
        return NGX_ERROR;
    }

    line++;

    while (line < header_end) {
        next = ngx_strlchr(line, header_end, '\n');
        if (next == NULL) {
            next = header_end;
        }

        line_end = next;
        if (line_end > line && line_end[-1] == '\r') {
            line_end--;
        }

        colon = ngx_strlchr(line, line_end, ':');

        if (colon
            && (size_t) (colon - line) == match->header_name.len
            && ngx_strncasecmp(line, match->header_name.data,
                               match->header_name.len)
               == 0)
        {
            value = colon + 1;

            while (value < line_end && (*value == ' ' || *value == '\t')) {
                value++;
            }

            while (line_end > value
                   && (line_end[-1] == ' ' || line_end[-1] == '\t'))
            {
                line_end--;
            }

            if ((size_t) (line_end - value) == match->header_value.len
                && ngx_memcmp(value, match->header_value.data,
                              match->header_value.len)
                   == 0)
            {
                return NGX_OK;
            }
        }

        line = (next == header_end) ? header_end : next + 1;
    }

    return NGX_ERROR;
}


static u_char *
ngx_http_upstream_hc_find(u_char *buf, size_t len, u_char *needle,
    size_t nlen)
{
    size_t  i;

    if (nlen == 0) {
        return buf;
    }

    if (len < nlen) {
        return NULL;
    }

    for (i = 0; i <= len - nlen; i++) {
        if (buf[i] == needle[0] && ngx_memcmp(&buf[i], needle, nlen) == 0) {
            return &buf[i];
        }
    }

    return NULL;
}


static ngx_http_upstream_hc_match_t *
ngx_http_upstream_hc_find_match(ngx_http_upstream_hc_main_conf_t *hmcf,
    ngx_str_t *name)
{
    ngx_uint_t                    i;
    ngx_http_upstream_hc_match_t *match;

    match = hmcf->matches->elts;

    for (i = 0; i < hmcf->matches->nelts; i++) {
        if (match[i].name.len == name->len
            && ngx_memcmp(match[i].name.data, name->data, name->len) == 0)
        {
            return &match[i];
        }
    }

    return NULL;
}
