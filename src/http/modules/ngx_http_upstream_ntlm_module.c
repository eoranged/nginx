/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_upstream_round_robin.h>
#include <ngx_http_upstream_keepalive_module.h>


typedef struct {
    ngx_queue_t                        cache;
    ngx_http_upstream_init_peer_pt     original_init_peer;
    ngx_uint_t                         enabled; /* unsigned  enabled:1; */
} ngx_http_upstream_ntlm_srv_conf_t;


typedef struct {
    ngx_http_upstream_ntlm_srv_conf_t  *conf;
    ngx_http_request_t                 *request;

    void                              *data;
    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

    ngx_event_notify_peer_pt           original_notify;

    void                              *item;
} ngx_http_upstream_ntlm_peer_data_t;


typedef struct {
    ngx_queue_t                        queue;
    ngx_http_upstream_ntlm_srv_conf_t *conf;

    ngx_connection_t                  *connection;
    ngx_connection_t                  *client;
    ngx_atomic_uint_t                  client_number;

    socklen_t                          socklen;
    ngx_sockaddr_t                     sockaddr;

    ngx_uint_t                         queued; /* unsigned  queued:1; */
    ngx_uint_t                         closed; /* unsigned  closed:1; */
} ngx_http_upstream_ntlm_connection_t;


static ngx_int_t ngx_http_upstream_ntlm_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_ntlm_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_ntlm_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static ngx_uint_t ngx_http_upstream_ntlm_request(ngx_http_request_t *r);
static ngx_uint_t ngx_http_upstream_ntlm_response(ngx_http_request_t *r);
static ngx_uint_t ngx_http_upstream_ntlm_token(ngx_str_t *value);

static ngx_http_upstream_ntlm_connection_t *
    ngx_http_upstream_ntlm_lookup(ngx_http_upstream_ntlm_srv_conf_t *conf,
    ngx_connection_t *client, ngx_peer_connection_t *pc);
static ngx_http_upstream_ntlm_connection_t *
    ngx_http_upstream_ntlm_lookup_client(
    ngx_http_upstream_ntlm_srv_conf_t *conf, ngx_connection_t *client);
static ngx_int_t ngx_http_upstream_ntlm_save(ngx_peer_connection_t *pc,
    ngx_http_upstream_ntlm_peer_data_t *np);
static void ngx_http_upstream_ntlm_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_ntlm_close(
    ngx_http_upstream_ntlm_connection_t *item);
static void ngx_http_upstream_ntlm_close_connection(ngx_connection_t *c);
static void ngx_http_upstream_ntlm_cleanup(void *data);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_ntlm_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void ngx_http_upstream_ntlm_notify_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);

static void *ngx_http_upstream_ntlm_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_ntlm_init_main_conf(ngx_conf_t *cf,
    void *conf);
static char *ngx_http_upstream_ntlm(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_ntlm_commands[] = {

    { ngx_string("ntlm"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_ntlm,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ntlm_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    ngx_http_upstream_ntlm_init_main_conf, /* init main configuration */

    ngx_http_upstream_ntlm_create_conf,    /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_ntlm_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ntlm_module_ctx,    /* module context */
    ngx_http_upstream_ntlm_commands,       /* module directives */
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
ngx_http_upstream_ntlm_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t                              rc;
    ngx_http_upstream_t                   *u;
    ngx_http_upstream_ntlm_peer_data_t    *np;
    ngx_http_upstream_ntlm_srv_conf_t     *ncf;

    ncf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);

    np = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_ntlm_peer_data_t));
    if (np == NULL) {
        return NGX_ERROR;
    }

    rc = ncf->original_init_peer(r, us);
    if (rc != NGX_OK) {
        return rc;
    }

    u = r->upstream;

    np->conf = ncf;
    np->request = r;
    np->data = u->peer.data;
    np->original_get_peer = u->peer.get;
    np->original_free_peer = u->peer.free;

    u->peer.data = np;
    u->peer.get = ngx_http_upstream_ntlm_get_peer;
    u->peer.free = ngx_http_upstream_ntlm_free_peer;

#if (NGX_HTTP_SSL)
    np->original_set_session = u->peer.set_session;
    np->original_save_session = u->peer.save_session;
    u->peer.set_session = ngx_http_upstream_ntlm_set_session;
    u->peer.save_session = ngx_http_upstream_ntlm_save_session;
#endif

    if (u->peer.notify) {
        np->original_notify = u->peer.notify;
        u->peer.notify = ngx_http_upstream_ntlm_notify_peer;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_ntlm_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_int_t                              rc;
    ngx_connection_t                      *c;
    ngx_http_upstream_ntlm_peer_data_t    *np = data;
    ngx_http_upstream_ntlm_connection_t   *item;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "get ntlm peer");

    if (!ngx_http_upstream_ntlm_request(np->request)) {
        return np->original_get_peer(pc, np->data);
    }

    rc = ngx_http_upstream_keepalive_get_peer_no_cache(pc, np->data);
    if (rc != NGX_OK) {
        return rc;
    }

    item = ngx_http_upstream_ntlm_lookup(np->conf, np->request->connection,
                                         pc);
    if (item == NULL) {
        return NGX_OK;
    }

    ngx_queue_remove(&item->queue);
    item->queued = 0;

    c = item->connection;
    item->connection = NULL;
    np->item = item;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ntlm peer: using connection %p", c);

    c->idle = 0;
    c->sent = 0;
    c->data = NULL;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;

    return NGX_DONE;
}


static void
ngx_http_upstream_ntlm_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_connection_t                    *c;
    ngx_http_upstream_t                 *u;
    ngx_http_upstream_ntlm_peer_data_t  *np = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "free ntlm peer");

    u = np->request->upstream;
    c = pc->connection;

    if ((ngx_http_upstream_ntlm_request(np->request)
         || ngx_http_upstream_ntlm_response(np->request))
        && !(state & NGX_PEER_FAILED)
        && c != NULL
        && !c->read->eof
        && !c->read->error
        && !c->read->timedout
        && !c->write->error
        && !c->write->timedout
        && u->keepalive
        && u->request_body_sent
        && !ngx_terminate
        && !ngx_exiting
        && ngx_handle_read_event(c->read, 0) == NGX_OK)
    {
        if (ngx_http_upstream_ntlm_save(pc, np) == NGX_OK) {
            pc->connection = NULL;

        } else {
            u->keepalive = 0;
        }

    } else if (np->item) {
        ngx_http_upstream_ntlm_connection_t  *item = np->item;

        item->closed = 1;
        item->connection = NULL;
        np->item = NULL;
    }

    if (np->original_free_peer == ngx_http_upstream_free_round_robin_peer) {
        ngx_peer_connection_t  rrp_pc;

        rrp_pc = *pc;
        rrp_pc.data = np->data;

        ngx_http_upstream_rr_peer_stats(&rrp_pc, u->state);
    }

    np->original_free_peer(pc, np->data, state);
}


static ngx_uint_t
ngx_http_upstream_ntlm_request(ngx_http_request_t *r)
{
    if (r->headers_in.authorization == NULL) {
        return 0;
    }

    return ngx_http_upstream_ntlm_token(&r->headers_in.authorization->value);
}


static ngx_uint_t
ngx_http_upstream_ntlm_response(ngx_http_request_t *r)
{
    ngx_table_elt_t  *h;

    for (h = r->upstream->headers_in.www_authenticate; h; h = h->next) {
        if (ngx_http_upstream_ntlm_token(&h->value)) {
            return 1;
        }
    }

    return 0;
}


static ngx_uint_t
ngx_http_upstream_ntlm_token(ngx_str_t *value)
{
    u_char  *p, *last;

    p = value->data;
    last = value->data + value->len;

    while (p < last) {
        while (p < last && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }

        if ((size_t) (last - p) >= 4
            && ngx_strncasecmp(p, (u_char *) "NTLM", 4) == 0
            && (p + 4 == last || p[4] == ' ' || p[4] == '\t' || p[4] == ','))
        {
            return 1;
        }

        while (p < last && *p != ',') {
            p++;
        }
    }

    return 0;
}


static ngx_http_upstream_ntlm_connection_t *
ngx_http_upstream_ntlm_lookup(ngx_http_upstream_ntlm_srv_conf_t *conf,
    ngx_connection_t *client, ngx_peer_connection_t *pc)
{
    ngx_queue_t                            *q;
    ngx_http_upstream_ntlm_connection_t   *item;

    for (q = ngx_queue_head(&conf->cache);
         q != ngx_queue_sentinel(&conf->cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_connection_t, queue);

        if (item->client != client
            || item->client_number != client->number
            || item->closed
            || item->connection == NULL)
        {
            continue;
        }

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            return item;
        }
    }

    return NULL;
}


static ngx_http_upstream_ntlm_connection_t *
ngx_http_upstream_ntlm_lookup_client(ngx_http_upstream_ntlm_srv_conf_t *conf,
    ngx_connection_t *client)
{
    ngx_queue_t                            *q;
    ngx_http_upstream_ntlm_connection_t   *item;

    for (q = ngx_queue_head(&conf->cache);
         q != ngx_queue_sentinel(&conf->cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_connection_t, queue);

        if (item->client == client
            && item->client_number == client->number
            && !item->closed)
        {
            return item;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_upstream_ntlm_save(ngx_peer_connection_t *pc,
    ngx_http_upstream_ntlm_peer_data_t *np)
{
    ngx_pool_cleanup_t                   *cln;
    ngx_connection_t                     *c, *client;
    ngx_http_upstream_ntlm_connection_t  *item, *old;

    c = pc->connection;
    client = np->request->connection;
    item = np->item;

    if (item && item->closed) {
        return NGX_DECLINED;
    }

    if (item == NULL) {
        item = ngx_pcalloc(client->pool,
                           sizeof(ngx_http_upstream_ntlm_connection_t));
        if (item == NULL) {
            return NGX_ERROR;
        }

        ngx_queue_init(&item->queue);

        cln = ngx_pool_cleanup_add(client->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_upstream_ntlm_cleanup;
        cln->data = item;
    }

    old = ngx_http_upstream_ntlm_lookup_client(np->conf, client);
    if (old && old != item) {
        ngx_http_upstream_ntlm_close(old);
    }

    item->conf = np->conf;
    item->client = client;
    item->client_number = client->number;
    item->connection = c;
    item->socklen = pc->socklen;
    item->closed = 0;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    c->read->delayed = 0;
    ngx_add_timer(c->read, 60000);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_http_upstream_ntlm_dummy_handler;
    c->read->handler = ngx_http_upstream_ntlm_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    if (!item->queued) {
        ngx_queue_insert_head(&np->conf->cache, &item->queue);
        item->queued = 1;
    }

    np->item = NULL;

    if (c->read->ready) {
        ngx_http_upstream_ntlm_close_handler(c->read);
    }

    return NGX_OK;
}


static void
ngx_http_upstream_ntlm_close_handler(ngx_event_t *ev)
{
    int                                      n;
    char                                     buf[1];
    ngx_connection_t                       *c;
    ngx_http_upstream_ntlm_connection_t    *item;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ntlm close handler");

    c = ev->data;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    ngx_http_upstream_ntlm_close(item);
}


static void
ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ntlm dummy handler");
}


static void
ngx_http_upstream_ntlm_close(ngx_http_upstream_ntlm_connection_t *item)
{
    ngx_connection_t  *c;

    if (item == NULL || item->closed) {
        return;
    }

    item->closed = 1;

    if (item->queued) {
        ngx_queue_remove(&item->queue);
        item->queued = 0;
    }

    c = item->connection;
    item->connection = NULL;

    ngx_http_upstream_ntlm_close_connection(c);
}


static void
ngx_http_upstream_ntlm_close_connection(ngx_connection_t *c)
{
    if (c == NULL) {
        return;
    }

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_ntlm_close_connection;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


static void
ngx_http_upstream_ntlm_cleanup(void *data)
{
    ngx_http_upstream_ntlm_connection_t  *item = data;

    ngx_http_upstream_ntlm_close(item);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_ntlm_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t  *np = data;

    return np->original_set_session(pc, np->data);
}


static void
ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t  *np = data;

    np->original_save_session(pc, np->data);
}

#endif


static void
ngx_http_upstream_ntlm_notify_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_upstream_ntlm_peer_data_t  *np = data;

    np->original_notify(pc, np->data, type);
}


static void *
ngx_http_upstream_ntlm_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_ntlm_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ntlm_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_queue_init(&conf->cache);

    return conf;
}


static char *
ngx_http_upstream_ntlm_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                            i;
    ngx_http_upstream_srv_conf_t        **uscfp;
    ngx_http_upstream_main_conf_t        *umcf;
    ngx_http_upstream_ntlm_srv_conf_t    *ncf;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->srv_conf == NULL) {
            continue;
        }

        ncf = ngx_http_conf_upstream_srv_conf(uscfp[i],
                                              ngx_http_upstream_ntlm_module);

        if (!ncf->enabled) {
            continue;
        }

        if (!ngx_http_upstream_keepalive_configured(uscfp[i])) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"ntlm\" requires \"keepalive\"");
            return NGX_CONF_ERROR;
        }

        ncf->original_init_peer = uscfp[i]->peer.init;
        uscfp[i]->peer.init = ngx_http_upstream_ntlm_init_peer;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_ntlm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_ntlm_srv_conf_t  *ncf = conf;

    if (ncf->enabled) {
        return "is duplicate";
    }

    ncf->enabled = 1;

    return NGX_CONF_OK;
}
