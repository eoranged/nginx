
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>


#define NGX_HTTP_AUTH_JWT_OFF        0
#define NGX_HTTP_AUTH_JWT_SIGNED     1
#define NGX_HTTP_AUTH_JWT_ENCRYPTED  2
#define NGX_HTTP_AUTH_JWT_NESTED     3

#define NGX_HTTP_AUTH_JWT_CLAIM      0
#define NGX_HTTP_AUTH_JWT_HEADER     1


typedef struct {
    ngx_str_t                  name;
    ngx_array_t               *keys;
    ngx_uint_t                 type;
} ngx_http_auth_jwt_var_t;


typedef struct {
    ngx_http_complex_value_t   left;
    ngx_uint_t                 code;
} ngx_http_auth_jwt_require_t;


typedef struct {
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t  *token;
    ngx_http_complex_value_t  *key_file;
    ngx_http_complex_value_t  *key_request;
    time_t                    key_cache;
    ngx_str_t                 cache_key;
    ngx_str_t                 cache;
    time_t                    cache_expire;
    ngx_uint_t                type;
    ngx_array_t              *vars;
    ngx_array_t              *requires;
} ngx_http_auth_jwt_loc_conf_t;


typedef struct {
    ngx_str_t                  kid;
    ngx_str_t                  kty;
    ngx_str_t                  k;
    ngx_str_t                  pem;
    ngx_str_t                  n;
    ngx_str_t                  e;
    ngx_str_t                  x;
    ngx_str_t                  y;
    ngx_str_t                  crv;
    time_t                     nbf;
    time_t                     exp;
} ngx_http_auth_jwt_key_t;


typedef struct {
    ngx_uint_t                 done;
    ngx_uint_t                 status;
    ngx_http_request_t        *subrequest;
    ngx_array_t               *header;
    ngx_array_t               *payload;
    ngx_str_t                  header_json;
    ngx_str_t                  payload_json;
    ngx_str_t                  request_jwks;
} ngx_http_auth_jwt_ctx_t;


static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_jwt_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_auth_jwt(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_jwt_type(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_jwt_key_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_jwt_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_jwt_require(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_auth_jwt_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_payload_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_jwt_conf_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_auth_jwt_validate(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *alcf, ngx_str_t *token,
    ngx_http_auth_jwt_ctx_t *ctx);
static ngx_int_t ngx_http_auth_jwt_verify(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *alcf, ngx_http_auth_jwt_ctx_t *ctx,
    ngx_str_t *alg, ngx_str_t *kid, ngx_str_t *signed_data,
    ngx_str_t *signature);
static ngx_int_t ngx_http_auth_jwt_key_request(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *alcf, ngx_http_auth_jwt_ctx_t *ctx);
static ngx_int_t ngx_http_auth_jwt_key_request_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

static ngx_int_t ngx_http_auth_jwt_json_get(ngx_pool_t *pool, ngx_str_t *json,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_auth_jwt_json_pairs(ngx_pool_t *pool,
    ngx_str_t *json, ngx_array_t **out);
static ngx_int_t ngx_http_auth_jwt_array_value(ngx_array_t *a,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_auth_jwt_json_lookup(ngx_pool_t *pool,
    ngx_str_t *json, ngx_array_t *names, ngx_str_t *value);


static ngx_command_t  ngx_http_auth_jwt_commands[] = {

    { ngx_string("auth_jwt"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_auth_jwt,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_jwt_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, key_file),
      NULL },

    { ngx_string("auth_jwt_key_request"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_jwt_loc_conf_t, key_request),
      NULL },

    { ngx_string("auth_jwt_key_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_jwt_key_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_jwt_type"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_jwt_type,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_jwt_claim_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_auth_jwt_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) NGX_HTTP_AUTH_JWT_CLAIM,
      },

    { ngx_string("auth_jwt_header_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_auth_jwt_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) NGX_HTTP_AUTH_JWT_HEADER,
      },

    { ngx_string("auth_jwt_require"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_auth_jwt_require,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_jwt_module_ctx = {
    ngx_http_auth_jwt_add_variables,       /* preconfiguration */
    ngx_http_auth_jwt_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_jwt_create_loc_conf,     /* create location configuration */
    ngx_http_auth_jwt_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_auth_jwt_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_jwt_module_ctx,         /* module context */
    ngx_http_auth_jwt_commands,            /* module directives */
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


static ngx_str_t  ngx_http_auth_jwt_claim_prefix =
    ngx_string("jwt_claim_");
static ngx_str_t  ngx_http_auth_jwt_header_prefix =
    ngx_string("jwt_header_");
static ngx_str_t  ngx_http_auth_jwt_payload_name =
    ngx_string("jwt_payload");


static ngx_int_t
ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_str_t                     realm, token, val;
    ngx_uint_t                    i;
    ngx_table_elt_t              *h;
    ngx_http_auth_jwt_ctx_t      *ctx;
    ngx_http_auth_jwt_require_t  *req;
    ngx_http_auth_jwt_loc_conf_t *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

    if (alcf->realm == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);

    if (ctx && ctx->subrequest) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status < NGX_HTTP_OK
            || ctx->status >= NGX_HTTP_SPECIAL_RESPONSE
            || ctx->subrequest->out == NULL
            || ctx->subrequest->out->buf == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_jwt_key_request unexpected status: %ui",
                          ctx->status);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->request_jwks.data = ctx->subrequest->out->buf->pos;
        ctx->request_jwks.len = ctx->subrequest->out->buf->last
                                - ctx->subrequest->out->buf->pos;
        ctx->subrequest = NULL;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_jwt_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_auth_jwt_module);
    }

    ngx_str_null(&token);

    if (alcf->token) {
        if (ngx_http_complex_value(r, alcf->token, &token) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        h = r->headers_in.authorization;

        if (h == NULL || h->value.len < sizeof("Bearer ") - 1
            || ngx_strncasecmp(h->value.data, (u_char *) "Bearer ",
                               sizeof("Bearer ") - 1)
               != 0)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "no jwt token was provided");
            goto unauthorized;
        }

        token.data = h->value.data + sizeof("Bearer ") - 1;
        token.len = h->value.len - (sizeof("Bearer ") - 1);
    }

    if (token.len == 0) {
        goto unauthorized;
    }

    rc = ngx_http_auth_jwt_validate(r, alcf, &token, ctx);

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK) {
        goto unauthorized;
    }

    if (alcf->requires) {
        req = alcf->requires->elts;

        for (i = 0; i < alcf->requires->nelts; i++) {
            if (ngx_http_complex_value(r, &req[i].left, &val) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (val.len == 0 || (val.len == 1 && val.data[0] == '0'))
            {
                return req[i].code;
            }
        }
    }

    return NGX_OK;

unauthorized:

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "WWW-Authenticate");
    h->value.len = sizeof("Bearer realm=\"\"") - 1 + realm.len;
    h->value.data = ngx_pnalloc(r->pool, h->value.len + 1);
    if (h->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_sprintf(h->value.data, "Bearer realm=\"%V\"", &realm);
    r->headers_out.www_authenticate = h;

    return NGX_HTTP_UNAUTHORIZED;
}


static ngx_int_t
ngx_http_auth_jwt_validate(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *alcf, ngx_str_t *token,
    ngx_http_auth_jwt_ctx_t *ctx)
{
    time_t                    now, n;
    ngx_str_t                 p[5], alg, kid, exp, nbf, iat;
    ngx_str_t                 header64, payload64, sig64, signed_data;
    ngx_uint_t                i, parts;

    parts = 1;
    p[0].data = token->data;

    for (i = 0; i < token->len; i++) {
        if (token->data[i] == '.') {
            if (parts == 5) {
                return NGX_DECLINED;
            }

            p[parts - 1].len = token->data + i - p[parts - 1].data;
            p[parts].data = token->data + i + 1;
            parts++;
        }
    }

    p[parts - 1].len = token->data + token->len - p[parts - 1].data;

    if (alcf->type != NGX_HTTP_AUTH_JWT_SIGNED) {
        return NGX_DECLINED;
    }

    if (parts != 3 || p[0].len == 0 || p[1].len == 0 || p[2].len == 0) {
        return NGX_DECLINED;
    }

    header64 = p[0];
    payload64 = p[1];
    sig64 = p[2];

    p[0].data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(header64.len));
    p[1].data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(payload64.len));
    p[2].data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(sig64.len));
    if (p[0].data == NULL || p[1].data == NULL || p[2].data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&p[0], &header64) != NGX_OK
        || ngx_decode_base64url(&p[1], &payload64) != NGX_OK
        || ngx_decode_base64url(&p[2], &sig64) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (ngx_http_auth_jwt_json_pairs(r->pool, &p[0], &ctx->header) != NGX_OK
        || ngx_http_auth_jwt_json_pairs(r->pool, &p[1], &ctx->payload)
           != NGX_OK)
    {
        return NGX_DECLINED;
    }

    ctx->header_json = p[0];
    ctx->payload_json = p[1];

    ngx_str_set(&alg, "alg");
    if (ngx_http_auth_jwt_array_value(ctx->header, &alg, &alg) != NGX_OK) {
        return NGX_DECLINED;
    }

    ngx_str_set(&kid, "kid");
    if (ngx_http_auth_jwt_array_value(ctx->header, &kid, &kid) != NGX_OK) {
        ngx_str_null(&kid);
    }

    signed_data.data = token->data;
    signed_data.len = header64.len + 1 + payload64.len;

    n = ngx_http_auth_jwt_verify(r, alcf, ctx, &alg, &kid, &signed_data,
                                  &p[2]);

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (n != NGX_OK) {
        return NGX_DECLINED;
    }

    now = ngx_time();

    ngx_str_set(&exp, "exp");
    if (ngx_http_auth_jwt_array_value(ctx->payload, &exp, &exp) == NGX_OK) {
        n = ngx_atoi(exp.data, exp.len);
        if (n == NGX_ERROR || n <= now) {
            return NGX_DECLINED;
        }
    }

    ngx_str_set(&nbf, "nbf");
    if (ngx_http_auth_jwt_array_value(ctx->payload, &nbf, &nbf) == NGX_OK) {
        n = ngx_atoi(nbf.data, nbf.len);
        if (n == NGX_ERROR || n > now) {
            return NGX_DECLINED;
        }
    }

    ngx_str_set(&iat, "iat");
    if (ngx_http_auth_jwt_array_value(ctx->payload, &iat, &iat) == NGX_OK) {
        n = ngx_atoi(iat.data, iat.len);
        if (n == NGX_ERROR || n > now) {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_read_file(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *content)
{
    size_t           size;
    ssize_t          n;
    ngx_fd_t         fd;
    ngx_file_t       file;
    ngx_file_info_t  fi;
    u_char          *path;

    path = ngx_pnalloc(r->pool, name->len + 1);
    if (path == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(path, name->data, name->len);
    path[name->len] = '\0';

    fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", name);
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = *name;
    file.log = r->connection->log;

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_fd_info_n " \"%V\" failed", name);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    size = (size_t) ngx_file_size(&fi);
    content->data = ngx_pnalloc(r->pool, size);
    if (content->data == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&file, content->data, size, 0);
    ngx_close_file(fd);

    if (n == NGX_ERROR || (size_t) n != size) {
        return NGX_ERROR;
    }

    content->len = size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_key_value(ngx_pool_t *pool, ngx_str_t *object,
    char *name, ngx_str_t *value)
{
    ngx_str_t  key;

    key.len = ngx_strlen(name);
    key.data = (u_char *) name;

    return ngx_http_auth_jwt_json_get(pool, object, &key, value);
}


static ngx_int_t
ngx_http_auth_jwt_next_key(ngx_pool_t *pool, ngx_str_t *jwks, ngx_uint_t *pos,
    ngx_http_auth_jwt_key_t *key)
{
    u_char     *p, *last, *start;
    ngx_int_t   depth;
    ngx_str_t   obj, v;

    p = jwks->data + *pos;
    last = jwks->data + jwks->len;

    while (p < last && *p != '{') {
        p++;
    }

    if (p == last) {
        return NGX_DONE;
    }

    start = p;
    depth = 0;

    while (p < last) {
        if (*p == '"') {
            p++;
            while (p < last) {
                if (*p == '\\') {
                    p += 2;
                    continue;
                }
                if (*p++ == '"') {
                    break;
                }
            }
            continue;
        }

        if (*p == '{') {
            depth++;
        }

        if (*p == '}') {
            depth--;
            if (depth == 0) {
                p++;
                break;
            }
        }

        p++;
    }

    if (depth != 0) {
        return NGX_ERROR;
    }

    *pos = p - jwks->data;
    obj.data = start;
    obj.len = p - start;

    ngx_memzero(key, sizeof(ngx_http_auth_jwt_key_t));

    if (ngx_http_auth_jwt_key_value(pool, &obj, "kid", &key->kid) != NGX_OK) {
        ngx_str_null(&key->kid);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "kty", &key->kty) != NGX_OK) {
        ngx_str_null(&key->kty);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "k", &key->k) != NGX_OK) {
        ngx_str_null(&key->k);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "pem", &key->pem) != NGX_OK) {
        ngx_str_null(&key->pem);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "n", &key->n) != NGX_OK) {
        ngx_str_null(&key->n);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "e", &key->e) != NGX_OK) {
        ngx_str_null(&key->e);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "x", &key->x) != NGX_OK) {
        ngx_str_null(&key->x);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "y", &key->y) != NGX_OK) {
        ngx_str_null(&key->y);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "crv", &key->crv) != NGX_OK) {
        ngx_str_null(&key->crv);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "nbf", &v) == NGX_OK) {
        key->nbf = ngx_atoi(v.data, v.len);
    }

    if (ngx_http_auth_jwt_key_value(pool, &obj, "exp", &v) == NGX_OK) {
        key->exp = ngx_atoi(v.data, v.len);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_key_match(ngx_http_auth_jwt_key_t *key, ngx_str_t *kid)
{
    if (kid->len == 0) {
        return NGX_OK;
    }

    if (key->kid.len != kid->len) {
        return NGX_DECLINED;
    }

    return ngx_strncmp(key->kid.data, kid->data, kid->len) == 0
           ? NGX_OK : NGX_DECLINED;
}


static ngx_int_t
ngx_http_auth_jwt_alg_is(ngx_str_t *alg, char *name)
{
    size_t  len;

    len = ngx_strlen(name);

    return alg->len == len && ngx_strncmp(alg->data, name, len) == 0;
}


static ngx_int_t
ngx_http_auth_jwt_mem_eq(u_char *a, u_char *b, size_t len)
{
    u_char    diff;
    ngx_uint_t i;

    diff = 0;

    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

    return diff == 0 ? NGX_OK : NGX_DECLINED;
}


static ngx_int_t
ngx_http_auth_jwt_hmac(ngx_http_request_t *r, ngx_http_auth_jwt_key_t *key,
    ngx_str_t *signed_data, ngx_str_t *signature)
{
    u_char      md[EVP_MAX_MD_SIZE];
    ngx_str_t   secret;
    unsigned    mdlen;

    if (key->k.len == 0) {
        return NGX_DECLINED;
    }

    secret.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(key->k.len));
    if (secret.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&secret, &key->k) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (HMAC(EVP_sha256(), secret.data, (int) secret.len, signed_data->data,
             signed_data->len, md, &mdlen)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (signature->len != mdlen
        || ngx_http_auth_jwt_mem_eq(signature->data, md, mdlen) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_ecdsa_der(ngx_http_request_t *r, ngx_str_t *raw,
    ngx_str_t *der)
{
    int         len;
    u_char     *p;
    BIGNUM     *bnr, *bns;
    ECDSA_SIG  *sig;

    if (raw->len != 64) {
        return NGX_DECLINED;
    }

    bnr = BN_bin2bn(raw->data, 32, NULL);
    bns = BN_bin2bn(raw->data + 32, 32, NULL);
    sig = ECDSA_SIG_new();

    if (bnr == NULL || bns == NULL || sig == NULL) {
        if (bnr) {
            BN_free(bnr);
        }
        if (bns) {
            BN_free(bns);
        }
        if (sig) {
            ECDSA_SIG_free(sig);
        }
        return NGX_ERROR;
    }

    if (ECDSA_SIG_set0(sig, bnr, bns) != 1) {
        BN_free(bnr);
        BN_free(bns);
        ECDSA_SIG_free(sig);
        return NGX_ERROR;
    }

    len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0) {
        ECDSA_SIG_free(sig);
        return NGX_ERROR;
    }

    der->data = ngx_pnalloc(r->pool, len);
    if (der->data == NULL) {
        ECDSA_SIG_free(sig);
        return NGX_ERROR;
    }

    p = der->data;
    len = i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);

    if (len <= 0) {
        return NGX_ERROR;
    }

    der->len = len;

    return NGX_OK;
}


static BIGNUM *
ngx_http_auth_jwt_bignum(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_str_t  raw;

    raw.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(value->len));
    if (raw.data == NULL) {
        return NULL;
    }

    if (ngx_decode_base64url(&raw, value) != NGX_OK) {
        return NULL;
    }

    return BN_bin2bn(raw.data, raw.len, NULL);
}


static EVP_PKEY *
ngx_http_auth_jwt_rsa_pkey(ngx_http_request_t *r,
    ngx_http_auth_jwt_key_t *key)
{
    RSA       *rsa;
    BIGNUM    *n, *e;
    EVP_PKEY  *pkey;

    if (key->n.len == 0 || key->e.len == 0) {
        return NULL;
    }

    n = ngx_http_auth_jwt_bignum(r, &key->n);
    e = ngx_http_auth_jwt_bignum(r, &key->e);
    rsa = RSA_new();

    if (n == NULL || e == NULL || rsa == NULL) {
        if (n) {
            BN_free(n);
        }
        if (e) {
            BN_free(e);
        }
        if (rsa) {
            RSA_free(rsa);
        }
        return NULL;
    }

    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        return NULL;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(rsa);
        return NULL;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}


static EVP_PKEY *
ngx_http_auth_jwt_ec_pkey(ngx_http_request_t *r, ngx_http_auth_jwt_key_t *key)
{
    EC_KEY    *ec;
    BIGNUM    *x, *y;
    EVP_PKEY  *pkey;

    if (key->x.len == 0 || key->y.len == 0
        || key->crv.len != sizeof("P-256") - 1
        || ngx_strncmp(key->crv.data, "P-256", sizeof("P-256") - 1) != 0)
    {
        return NULL;
    }

    x = ngx_http_auth_jwt_bignum(r, &key->x);
    y = ngx_http_auth_jwt_bignum(r, &key->y);
    ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if (x == NULL || y == NULL || ec == NULL) {
        if (x) {
            BN_free(x);
        }
        if (y) {
            BN_free(y);
        }
        if (ec) {
            EC_KEY_free(ec);
        }
        return NULL;
    }

    if (EC_KEY_set_public_key_affine_coordinates(ec, x, y) != 1) {
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec);
        return NULL;
    }

    BN_free(x);
    BN_free(y);

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        EC_KEY_free(ec);
        return NULL;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        EC_KEY_free(ec);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}


static EVP_PKEY *
ngx_http_auth_jwt_pkey(ngx_http_request_t *r, ngx_http_auth_jwt_key_t *key,
    ngx_str_t *alg)
{
    BIO       *bio;
    EVP_PKEY  *pkey;

    if (ngx_http_auth_jwt_alg_is(alg, "RS256")
        || ngx_http_auth_jwt_alg_is(alg, "PS256"))
    {
        pkey = ngx_http_auth_jwt_rsa_pkey(r, key);
        if (pkey) {
            return pkey;
        }
    }

    if (ngx_http_auth_jwt_alg_is(alg, "ES256")) {
        pkey = ngx_http_auth_jwt_ec_pkey(r, key);
        if (pkey) {
            return pkey;
        }
    }

    if (key->pem.len == 0) {
        return NULL;
    }

    bio = BIO_new_mem_buf(key->pem.data, (int) key->pem.len);
    if (bio == NULL) {
        return NULL;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return pkey;
}


static ngx_int_t
ngx_http_auth_jwt_evp(ngx_http_request_t *r, ngx_http_auth_jwt_key_t *key,
    ngx_str_t *alg, ngx_str_t *signed_data, ngx_str_t *signature)
{
    int           rc;
    ngx_str_t     sig;
    EVP_PKEY     *pkey;
    EVP_MD_CTX   *ctx;
    EVP_PKEY_CTX *pctx;

    sig = *signature;

    if (ngx_http_auth_jwt_alg_is(alg, "ES256")) {
        rc = ngx_http_auth_jwt_ecdsa_der(r, signature, &sig);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    pkey = ngx_http_auth_jwt_pkey(r, key, alg);
    if (pkey == NULL) {
        return NGX_DECLINED;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NGX_ERROR;
    }

    rc = EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey);
    EVP_PKEY_free(pkey);

    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        return NGX_ERROR;
    }

    if (ngx_http_auth_jwt_alg_is(alg, "PS256")) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return NGX_ERROR;
        }
    }

    rc = EVP_DigestVerifyUpdate(ctx, signed_data->data, signed_data->len);
    if (rc == 1) {
        rc = EVP_DigestVerifyFinal(ctx, sig.data, sig.len);
    }

    EVP_MD_CTX_free(ctx);

    return rc == 1 ? NGX_OK : NGX_DECLINED;
}


static ngx_int_t
ngx_http_auth_jwt_key_cache_save(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *alcf, ngx_str_t *key, ngx_str_t *jwks)
{
    u_char  *p;
    u_char  *k;

    if (alcf->key_cache == 0 || jwks->len == 0) {
        return NGX_OK;
    }

    p = ngx_alloc(jwks->len, r->connection->log);
    if (p == NULL) {
        return NGX_ERROR;
    }

    k = ngx_alloc(key->len, r->connection->log);
    if (k == NULL) {
        ngx_free(p);
        return NGX_ERROR;
    }

    ngx_memcpy(p, jwks->data, jwks->len);
    ngx_memcpy(k, key->data, key->len);

    if (alcf->cache.data) {
        ngx_free(alcf->cache.data);
    }

    if (alcf->cache_key.data) {
        ngx_free(alcf->cache_key.data);
    }

    alcf->cache.data = p;
    alcf->cache.len = jwks->len;
    alcf->cache_key.data = k;
    alcf->cache_key.len = key->len;
    alcf->cache_expire = ngx_time() + alcf->key_cache;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_key_cache_get(ngx_http_auth_jwt_loc_conf_t *alcf,
    ngx_str_t *key, ngx_str_t *jwks)
{
    if (alcf->key_cache == 0 || alcf->cache.len == 0
        || alcf->cache_expire <= ngx_time()
        || alcf->cache_key.len != key->len
        || ngx_strncmp(alcf->cache_key.data, key->data, key->len) != 0)
    {
        return NGX_DECLINED;
    }

    *jwks = alcf->cache;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_key_request(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *alcf, ngx_http_auth_jwt_ctx_t *ctx)
{
    ngx_str_t                    uri;
    ngx_http_request_t          *sr;
    ngx_http_post_subrequest_t  *ps;

    if (ngx_http_complex_value(r, alcf->key_request, &uri) != NGX_OK) {
        return NGX_ERROR;
    }

    if (uri.len == 0 || uri.data[0] != '/') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid auth_jwt_key_request URI \"%V\"", &uri);
        return NGX_ERROR;
    }

    if (ngx_http_auth_jwt_key_cache_get(alcf, &uri, &ctx->request_jwks)
        == NGX_OK)
    {
        return NGX_OK;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_auth_jwt_key_request_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY
                            |NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sr->header_only = 0;
    ctx->subrequest = sr;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_auth_jwt_key_request_done(ngx_http_request_t *r, void *data,
    ngx_int_t rc)
{
    ngx_http_auth_jwt_ctx_t  *ctx = data;

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static ngx_int_t
ngx_http_auth_jwt_verify(ngx_http_request_t *r,
    ngx_http_auth_jwt_loc_conf_t *alcf, ngx_http_auth_jwt_ctx_t *ctx,
    ngx_str_t *alg, ngx_str_t *kid, ngx_str_t *signed_data,
    ngx_str_t *signature)
{
    time_t                   now;
    ngx_int_t                rc;
    ngx_str_t                name, jwks;
    ngx_uint_t               pos, found;
    ngx_http_auth_jwt_key_t  key;

    if (!ngx_http_auth_jwt_alg_is(alg, "HS256")
        && !ngx_http_auth_jwt_alg_is(alg, "RS256")
        && !ngx_http_auth_jwt_alg_is(alg, "PS256")
        && !ngx_http_auth_jwt_alg_is(alg, "ES256"))
    {
        return NGX_DECLINED;
    }

    if (alcf->key_file) {
        if (ngx_http_complex_value(r, alcf->key_file, &name) != NGX_OK) {
            return NGX_ERROR;
        }

        if (alcf->key_file->lengths == NULL
            && ngx_http_auth_jwt_key_cache_get(alcf, &name, &jwks) == NGX_OK)
        {
            goto loaded;
        }

        if (ngx_http_auth_jwt_read_file(r, &name, &jwks) != NGX_OK) {
            return NGX_ERROR;
        }

        if (alcf->key_file->lengths == NULL
            && ngx_http_auth_jwt_key_cache_save(r, alcf, &name, &jwks)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (alcf->key_request) {
        if (ctx->request_jwks.len == 0) {
            rc = ngx_http_auth_jwt_key_request(r, alcf, ctx);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        jwks = ctx->request_jwks;

        if (alcf->key_cache && alcf->key_request->lengths == NULL
            && ngx_http_complex_value(r, alcf->key_request, &name) == NGX_OK
            && ngx_http_auth_jwt_key_cache_get(alcf, &name, &jwks)
               != NGX_OK
            && ngx_http_auth_jwt_key_cache_save(r, alcf, &name, &jwks)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        return NGX_ERROR;
    }

loaded:

    for (pos = 0; pos < jwks.len; pos++) {
        if (jwks.data[pos] == '[') {
            pos++;
            break;
        }
    }

    if (pos == jwks.len) {
        return NGX_ERROR;
    }

    found = 0;
    now = ngx_time();

    for ( ;; ) {
        rc = ngx_http_auth_jwt_next_key(r->pool, &jwks, &pos, &key);

        if (rc == NGX_DONE) {
            break;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_auth_jwt_key_match(&key, kid) != NGX_OK) {
            continue;
        }

        found = 1;

        if ((key.nbf && key.nbf > now) || (key.exp && key.exp <= now)) {
            return NGX_DECLINED;
        }

        if (ngx_http_auth_jwt_alg_is(alg, "HS256")) {
            rc = ngx_http_auth_jwt_hmac(r, &key, signed_data, signature);
        } else {
            rc = ngx_http_auth_jwt_evp(r, &key, alg, signed_data, signature);
        }

        if (rc == NGX_OK || rc == NGX_ERROR) {
            return rc;
        }
    }

    return found ? NGX_DECLINED : NGX_DECLINED;
}


static ngx_int_t
ngx_http_auth_jwt_hex(u_char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    c = ngx_tolower(c);

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_auth_jwt_json_string(ngx_pool_t *pool, u_char **pp, u_char *last,
    ngx_str_t *value)
{
    u_char     *p, *dst;
    ngx_uint_t  len;

    p = *pp;

    if (p == last || *p != '"') {
        return NGX_DECLINED;
    }

    p++;
    len = 0;

    while (p < last) {
        if (*p == '"') {
            break;
        }

        if (*p == '\\') {
            p++;
            if (p == last) {
                return NGX_DECLINED;
            }
        }

        len++;
        p++;
    }

    if (p == last) {
        return NGX_DECLINED;
    }

    value->data = ngx_pnalloc(pool, len);
    if (value->data == NULL) {
        return NGX_ERROR;
    }

    dst = value->data;
    p = *pp + 1;

    while (p < last && *p != '"') {
        if (*p == '\\') {
            p++;
            if (p == last) {
                return NGX_DECLINED;
            }

            switch (*p) {
            case '"':
            case '\\':
            case '/':
                *dst++ = *p++;
                break;
            case 'b':
                *dst++ = '\b'; p++;
                break;
            case 'f':
                *dst++ = '\f'; p++;
                break;
            case 'n':
                *dst++ = '\n'; p++;
                break;
            case 'r':
                *dst++ = '\r'; p++;
                break;
            case 't':
                *dst++ = '\t'; p++;
                break;
            case 'u':
                if (p + 4 >= last
                    || ngx_http_auth_jwt_hex(p[1]) == NGX_ERROR
                    || ngx_http_auth_jwt_hex(p[2]) == NGX_ERROR
                    || ngx_http_auth_jwt_hex(p[3]) == NGX_ERROR
                    || ngx_http_auth_jwt_hex(p[4]) == NGX_ERROR)
                {
                    return NGX_DECLINED;
                }
                *dst++ = '?';
                p += 5;
                break;
            default:
                return NGX_DECLINED;
            }

            continue;
        }

        *dst++ = *p++;
    }

    value->len = dst - value->data;
    *pp = p + 1;

    return NGX_OK;
}


static void
ngx_http_auth_jwt_json_skip_ws(u_char **pp, u_char *last)
{
    while (*pp < last
           && (**pp == ' ' || **pp == CR || **pp == LF || **pp == '\t'))
    {
        (*pp)++;
    }
}


static ngx_int_t
ngx_http_auth_jwt_json_value(ngx_pool_t *pool, u_char **pp, u_char *last,
    ngx_str_t *value)
{
    u_char     *p, *start;
    ngx_int_t   depth;

    ngx_http_auth_jwt_json_skip_ws(pp, last);

    p = *pp;

    if (p == last) {
        return NGX_DECLINED;
    }

    if (*p == '"') {
        return ngx_http_auth_jwt_json_string(pool, pp, last, value);
    }

    start = p;
    depth = 0;

    while (p < last) {
        if (*p == '"') {
            p++;
            while (p < last) {
                if (*p == '\\') {
                    p += 2;
                    continue;
                }
                if (*p++ == '"') {
                    break;
                }
            }
            continue;
        }

        if (*p == '{' || *p == '[') {
            depth++;
        }

        if (*p == '}' || *p == ']') {
            if (depth == 0) {
                break;
            }

            depth--;
            p++;

            if (depth == 0) {
                break;
            }

            continue;
        }

        if (depth == 0 && (*p == ',' || *p == '}' || *p == ']')) {
            break;
        }

        p++;
    }

    while (p > start && (p[-1] == ' ' || p[-1] == CR || p[-1] == LF
                         || p[-1] == '\t'))
    {
        p--;
    }

    value->data = start;
    value->len = p - start;
    *pp = p;

    return value->len ? NGX_OK : NGX_DECLINED;
}


static ngx_int_t
ngx_http_auth_jwt_json_get(ngx_pool_t *pool, ngx_str_t *json, ngx_str_t *name,
    ngx_str_t *value)
{
    u_char     *p, *last;
    ngx_str_t   key, v;
    ngx_int_t   rc;

    p = json->data;
    last = json->data + json->len;

    ngx_http_auth_jwt_json_skip_ws(&p, last);

    if (p == last || *p++ != '{') {
        return NGX_DECLINED;
    }

    for ( ;; ) {
        ngx_http_auth_jwt_json_skip_ws(&p, last);

        if (p == last || *p == '}') {
            return NGX_DECLINED;
        }

        rc = ngx_http_auth_jwt_json_string(pool, &p, last, &key);
        if (rc != NGX_OK) {
            return rc;
        }

        ngx_http_auth_jwt_json_skip_ws(&p, last);
        if (p == last || *p++ != ':') {
            return NGX_DECLINED;
        }

        rc = ngx_http_auth_jwt_json_value(pool, &p, last, &v);
        if (rc != NGX_OK) {
            return rc;
        }

        if (key.len == name->len
            && ngx_strncmp(key.data, name->data, name->len) == 0)
        {
            *value = v;
            return NGX_OK;
        }

        ngx_http_auth_jwt_json_skip_ws(&p, last);

        if (p < last && *p == ',') {
            p++;
            continue;
        }

        if (p < last && *p == '}') {
            return NGX_DECLINED;
        }

        return NGX_DECLINED;
    }
}


static ngx_int_t
ngx_http_auth_jwt_json_pairs(ngx_pool_t *pool, ngx_str_t *json,
    ngx_array_t **out)
{
    u_char         *p, *last;
    ngx_int_t       rc;
    ngx_keyval_t   *kv;

    *out = ngx_array_create(pool, 4, sizeof(ngx_keyval_t));
    if (*out == NULL) {
        return NGX_ERROR;
    }

    p = json->data;
    last = json->data + json->len;

    ngx_http_auth_jwt_json_skip_ws(&p, last);

    if (p == last || *p++ != '{') {
        return NGX_DECLINED;
    }

    for ( ;; ) {
        ngx_http_auth_jwt_json_skip_ws(&p, last);

        if (p < last && *p == '}') {
            return NGX_OK;
        }

        kv = ngx_array_push(*out);
        if (kv == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_http_auth_jwt_json_string(pool, &p, last, &kv->key);
        if (rc != NGX_OK) {
            return rc;
        }

        ngx_http_auth_jwt_json_skip_ws(&p, last);
        if (p == last || *p++ != ':') {
            return NGX_DECLINED;
        }

        rc = ngx_http_auth_jwt_json_value(pool, &p, last, &kv->value);
        if (rc != NGX_OK) {
            return rc;
        }

        ngx_http_auth_jwt_json_skip_ws(&p, last);

        if (p < last && *p == ',') {
            p++;
            continue;
        }

        if (p < last && *p == '}') {
            return NGX_OK;
        }

        return NGX_DECLINED;
    }
}


static ngx_int_t
ngx_http_auth_jwt_array_value(ngx_array_t *a, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t    i;
    ngx_keyval_t *kv;

    if (a == NULL) {
        return NGX_DECLINED;
    }

    kv = a->elts;

    for (i = 0; i < a->nelts; i++) {
        if (kv[i].key.len == name->len
            && ngx_strncmp(kv[i].key.data, name->data, name->len) == 0)
        {
            *value = kv[i].value;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_auth_jwt_json_array(ngx_pool_t *pool, ngx_str_t *json,
    ngx_str_t *value)
{
    u_char     *p, *last, *dst;
    size_t      len;
    ngx_int_t   rc;
    ngx_str_t   v, *elt;
    ngx_array_t *elts;
    ngx_uint_t  i;

    p = json->data;
    last = json->data + json->len;

    ngx_http_auth_jwt_json_skip_ws(&p, last);

    if (p == last || *p++ != '[') {
        return NGX_DECLINED;
    }

    elts = ngx_array_create(pool, 2, sizeof(ngx_str_t));
    if (elts == NULL) {
        return NGX_ERROR;
    }

    len = 0;

    for ( ;; ) {
        ngx_http_auth_jwt_json_skip_ws(&p, last);

        if (p < last && *p == ']') {
            break;
        }

        rc = ngx_http_auth_jwt_json_value(pool, &p, last, &v);
        if (rc != NGX_OK) {
            return rc;
        }

        elt = ngx_array_push(elts);
        if (elt == NULL) {
            return NGX_ERROR;
        }

        *elt = v;
        len += v.len;

        ngx_http_auth_jwt_json_skip_ws(&p, last);

        if (p < last && *p == ',') {
            p++;
            continue;
        }

        if (p < last && *p == ']') {
            break;
        }

        return NGX_DECLINED;
    }

    if (elts->nelts == 0) {
        ngx_str_null(value);
        return NGX_OK;
    }

    len += elts->nelts - 1;

    value->data = ngx_pnalloc(pool, len);
    if (value->data == NULL) {
        return NGX_ERROR;
    }

    dst = value->data;
    v = ((ngx_str_t *) elts->elts)[0];

    for (i = 0; i < elts->nelts; i++) {
        v = ((ngx_str_t *) elts->elts)[i];

        if (i != 0) {
            *dst++ = ',';
        }

        dst = ngx_cpymem(dst, v.data, v.len);
    }

    value->len = dst - value->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_json_normalize(ngx_pool_t *pool, ngx_str_t *json,
    ngx_str_t *value)
{
    u_char  *p, *last;

    p = json->data;
    last = json->data + json->len;

    ngx_http_auth_jwt_json_skip_ws(&p, last);

    if (p < last && *p == '[') {
        return ngx_http_auth_jwt_json_array(pool, json, value);
    }

    *value = *json;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_json_lookup(ngx_pool_t *pool, ngx_str_t *json,
    ngx_array_t *names, ngx_str_t *value)
{
    ngx_str_t   v, *name;
    ngx_uint_t  i;

    v = *json;
    name = names->elts;

    for (i = 0; i < names->nelts; i++) {
        if (ngx_http_auth_jwt_json_get(pool, &v, &name[i], &v) != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    return ngx_http_auth_jwt_json_normalize(pool, &v, value);
}


static ngx_int_t
ngx_http_auth_jwt_value(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_str_t *value)
{
    v->len = value->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = value->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_not_found(ngx_http_variable_value_t *v)
{
    v->not_found = 1;
    v->valid = 0;
    v->no_cacheable = 0;
    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                 *name, key, value;
    ngx_http_auth_jwt_ctx_t   *ctx;

    name = (ngx_str_t *) data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);

    if (ctx == NULL) {
        return ngx_http_auth_jwt_not_found(v);
    }

    if (name->len > ngx_http_auth_jwt_claim_prefix.len
        && ngx_strncmp(name->data, ngx_http_auth_jwt_claim_prefix.data,
                       ngx_http_auth_jwt_claim_prefix.len)
           == 0)
    {
        key.data = name->data + ngx_http_auth_jwt_claim_prefix.len;
        key.len = name->len - ngx_http_auth_jwt_claim_prefix.len;

        if (ngx_http_auth_jwt_array_value(ctx->payload, &key, &value)
            == NGX_OK)
        {
            if (ngx_http_auth_jwt_json_normalize(r->pool, &value, &value)
                != NGX_OK)
            {
                return ngx_http_auth_jwt_not_found(v);
            }

            return ngx_http_auth_jwt_value(r, v, &value);
        }
    }

    if (name->len > ngx_http_auth_jwt_header_prefix.len
        && ngx_strncmp(name->data, ngx_http_auth_jwt_header_prefix.data,
                       ngx_http_auth_jwt_header_prefix.len)
           == 0)
    {
        key.data = name->data + ngx_http_auth_jwt_header_prefix.len;
        key.len = name->len - ngx_http_auth_jwt_header_prefix.len;

        if (ngx_http_auth_jwt_array_value(ctx->header, &key, &value)
            == NGX_OK)
        {
            if (ngx_http_auth_jwt_json_normalize(r->pool, &value, &value)
                != NGX_OK)
            {
                return ngx_http_auth_jwt_not_found(v);
            }

            return ngx_http_auth_jwt_value(r, v, &value);
        }
    }

    return ngx_http_auth_jwt_not_found(v);
}


static ngx_int_t
ngx_http_auth_jwt_payload_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_jwt_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);

    if (ctx == NULL) {
        return ngx_http_auth_jwt_not_found(v);
    }

    return ngx_http_auth_jwt_value(r, v, &ctx->payload_json);
}


static ngx_int_t
ngx_http_auth_jwt_conf_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                  value;
    ngx_http_auth_jwt_ctx_t   *ctx;
    ngx_http_auth_jwt_var_t   *var;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
    var = (ngx_http_auth_jwt_var_t *) data;

    if (ctx == NULL) {
        return ngx_http_auth_jwt_not_found(v);
    }

    if (var->type == NGX_HTTP_AUTH_JWT_CLAIM) {
        if (ngx_http_auth_jwt_json_lookup(r->pool, &ctx->payload_json,
                                          var->keys, &value)
            == NGX_OK)
        {
            return ngx_http_auth_jwt_value(r, v, &value);
        }

    } else {
        if (ngx_http_auth_jwt_json_lookup(r->pool, &ctx->header_json,
                                          var->keys, &value)
            == NGX_OK)
        {
            return ngx_http_auth_jwt_value(r, v, &value);
        }
    }

    return ngx_http_auth_jwt_not_found(v);
}


static ngx_int_t
ngx_http_auth_jwt_compile(ngx_conf_t *cf, ngx_str_t *value,
    ngx_http_complex_value_t *cv)
{
    ngx_http_compile_complex_value_t  ccv;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = cv;

    return ngx_http_compile_complex_value(&ccv);
}


static char *
ngx_http_auth_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_jwt_loc_conf_t *alcf = conf;

    ngx_str_t   *value, s;
    ngx_uint_t   i;

    if (alcf->realm != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    alcf->realm = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (alcf->realm == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_auth_jwt_compile(cf, &value[1], alcf->realm) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {
        if (value[i].len > sizeof("token=") - 1
            && ngx_strncmp(value[i].data, "token=", sizeof("token=") - 1) == 0)
        {
            s.data = value[i].data + sizeof("token=") - 1;
            s.len = value[i].len - (sizeof("token=") - 1);

            alcf->token = ngx_palloc(cf->pool,
                                     sizeof(ngx_http_complex_value_t));
            if (alcf->token == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_auth_jwt_compile(cf, &s, alcf->token) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid auth_jwt parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_jwt_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_jwt_loc_conf_t *alcf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "signed") == 0) {
        alcf->type = NGX_HTTP_AUTH_JWT_SIGNED;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "encrypted") == 0) {
        alcf->type = NGX_HTTP_AUTH_JWT_ENCRYPTED;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "nested") == 0) {
        alcf->type = NGX_HTTP_AUTH_JWT_NESTED;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid auth_jwt_type \"%V\"", &value[1]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_auth_jwt_key_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_jwt_loc_conf_t *alcf = conf;

    ngx_int_t   n;
    ngx_str_t  *value;

    value = cf->args->elts;
    n = ngx_parse_time(&value[1], 1);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid auth_jwt_key_cache value \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    alcf->key_cache = n;

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_jwt_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_jwt_loc_conf_t *alcf = conf;

    ngx_str_t                 *value, name;
    ngx_uint_t                 i;
    ngx_str_t                 *key;
    ngx_http_variable_t       *v;
    ngx_http_auth_jwt_var_t   *var;

    value = cf->args->elts;

    if (value[1].len < 2 || value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (alcf->vars == NGX_CONF_UNSET_PTR) {
        alcf->vars = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_http_auth_jwt_var_t));
        if (alcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    var = ngx_array_push(alcf->vars);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data + 1;
    name.len = value[1].len - 1;

    var->name = name;
    var->type = (ngx_uint_t) (uintptr_t) cmd->post;
    var->keys = ngx_array_create(cf->pool, cf->args->nelts - 2,
                                 sizeof(ngx_str_t));
    if (var->keys == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {
        key = ngx_array_push(var->keys);
        if (key == NULL) {
            return NGX_CONF_ERROR;
        }

        *key = value[i];
    }

    v = ngx_http_add_variable(cf, &name,
                              NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    v->get_handler = ngx_http_auth_jwt_conf_variable;
    v->data = (uintptr_t) var;

    if (ngx_http_get_variable_index(cf, &name) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_jwt_require(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_jwt_loc_conf_t *alcf = conf;

    ngx_str_t                    *value;
    ngx_uint_t                    i, code;
    ngx_http_auth_jwt_require_t  *req;

    value = cf->args->elts;
    code = NGX_HTTP_UNAUTHORIZED;

    if (alcf->requires == NGX_CONF_UNSET_PTR) {
        alcf->requires = ngx_array_create(cf->pool, 2,
                                          sizeof(ngx_http_auth_jwt_require_t));
        if (alcf->requires == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == sizeof("error=401") - 1
            && ngx_strncmp(value[i].data, "error=401",
                           sizeof("error=401") - 1)
               == 0)
        {
            code = NGX_HTTP_UNAUTHORIZED;
            continue;
        }

        if (value[i].len == sizeof("error=403") - 1
            && ngx_strncmp(value[i].data, "error=403",
                           sizeof("error=403") - 1)
               == 0)
        {
            code = NGX_HTTP_FORBIDDEN;
            continue;
        }

        if (value[i].len >= sizeof("error=") - 1
            && ngx_strncmp(value[i].data, "error=", sizeof("error=") - 1)
               == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid auth_jwt_require parameter \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len >= sizeof("error=") - 1
            && ngx_strncmp(value[i].data, "error=", sizeof("error=") - 1)
               == 0)
        {
            continue;
        }

        req = ngx_array_push(alcf->requires);
        if (req == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(req, sizeof(ngx_http_auth_jwt_require_t));
        req->code = code;

        if (ngx_http_auth_jwt_compile(cf, &value[i], &req->left) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_jwt_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->realm = NGX_CONF_UNSET_PTR;
    conf->token = NGX_CONF_UNSET_PTR;
    conf->key_file = NGX_CONF_UNSET_PTR;
    conf->key_request = NGX_CONF_UNSET_PTR;
    conf->key_cache = NGX_CONF_UNSET;
    conf->type = NGX_CONF_UNSET_UINT;
    conf->vars = NGX_CONF_UNSET_PTR;
    conf->requires = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_jwt_loc_conf_t *prev = parent;
    ngx_http_auth_jwt_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->realm, prev->realm, NULL);
    ngx_conf_merge_ptr_value(conf->token, prev->token, NULL);
    ngx_conf_merge_ptr_value(conf->key_file, prev->key_file, NULL);
    ngx_conf_merge_ptr_value(conf->key_request, prev->key_request, NULL);
    ngx_conf_merge_sec_value(conf->key_cache, prev->key_cache, 0);
    ngx_conf_merge_uint_value(conf->type, prev->type,
                              NGX_HTTP_AUTH_JWT_SIGNED);
    ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);
    ngx_conf_merge_ptr_value(conf->requires, prev->requires, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_jwt_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_auth_jwt_claim_prefix,
                                NGX_HTTP_VAR_NOCACHEABLE
                                |NGX_HTTP_VAR_PREFIX);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_auth_jwt_variable;

    var = ngx_http_add_variable(cf, &ngx_http_auth_jwt_header_prefix,
                                NGX_HTTP_VAR_NOCACHEABLE
                                |NGX_HTTP_VAR_PREFIX);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_auth_jwt_variable;

    var = ngx_http_add_variable(cf, &ngx_http_auth_jwt_payload_name,
                                NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_auth_jwt_payload_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_jwt_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_jwt_handler;

    return NGX_OK;
}
