#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <gd.h>


#define NGX_HTTP_PNGQUANT_START     0
#define NGX_HTTP_PNGQUANT_READ      1
#define NGX_HTTP_PNGQUANT_PROCESS   2
#define NGX_HTTP_PNGQUANT_PASS      3
#define NGX_HTTP_PNGQUANT_DONE      4


#define NGX_HTTP_PNGQUANT_BUFFERED  0x08


typedef struct {
    ngx_flag_t                   quantize;
    size_t                       buffer_size;
    ngx_flag_t                   dither;
    ngx_uint_t                   colors;
    ngx_uint_t                   speed;
} ngx_http_pngquant_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;
    size_t                       length;
    ngx_uint_t                   phase;
} ngx_http_pngquant_ctx_t;


static void *ngx_http_pngquant_create_conf(ngx_conf_t *cf);
static char *ngx_http_pngquant_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_pngquant_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_pngquant_commands[] = {

    { ngx_string("pngquant"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, quantize),
      NULL },

    { ngx_string("pngquant_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, buffer_size),
      NULL },

    { ngx_string("pngquant_dither"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, dither),
      NULL },

    { ngx_string("pngquant_colors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, colors),
      NULL },

    { ngx_string("pngquant_speed"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, speed),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pngquant_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_pngquant_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_pngquant_create_conf,         /* create location configuration */
    ngx_http_pngquant_merge_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_pngquant_module = {
    NGX_MODULE_V1,
    &ngx_http_pngquant_module_ctx,         /* module context */
    ngx_http_pngquant_commands,            /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_str_t  ngx_http_pngquant_content_type[] = {
    ngx_string("image/png")
};


static ngx_int_t
ngx_http_pngquant_header_filter(ngx_http_request_t *r)
{
    off_t                     len;
    ngx_http_pngquant_ctx_t   *ctx;
    ngx_http_pngquant_conf_t  *conf;

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {

        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pngquant_module);

    if (ctx) {

        ngx_http_set_ctx(r, NULL, ngx_http_pngquant_module);

        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pngquant_module);

    if (!conf->quantize) {

        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_pngquant_ctx_t));

    if (ctx == NULL) {

        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_pngquant_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {

        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (len == -1) {

        ctx->length = conf->buffer_size;

    } else {

        ctx->length = (size_t) len;
    }

    if (r->headers_out.refresh) {

        r->headers_out.refresh->hash = 0;
    }

    r->main_filter_need_in_memory = 1;

    r->allow_ranges = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_pngquant_send(ngx_http_request_t *r, ngx_http_pngquant_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {

        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->phase == NGX_HTTP_PNGQUANT_DONE) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}


static ngx_uint_t
ngx_http_pngquant_is_png(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {

        return NGX_ERROR;
    }

    if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G' &&
        p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_pngquant_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                   *p;
    size_t                   size, rest;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_pngquant_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pngquant_module);

    if (ctx->image == NULL) {

        ctx->image = ngx_palloc(r->pool, ctx->length);

        if (ctx->image == NULL) {

            return NGX_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        rest = ctx->image + ctx->length - p;

        //too big response
        if (size > rest) {

            return NGX_ERROR;
        }

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {

            ctx->last = p;

            return NGX_OK;
        }
    }

    ctx->last = p;

    r->connection->buffered |= NGX_HTTP_PNGQUANT_BUFFERED;

    return NGX_AGAIN;
}


static void
ngx_http_pngquant_length(ngx_http_request_t *r, ngx_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}


static ngx_buf_t *
ngx_http_pngquant_asis(ngx_http_request_t *r, ngx_http_pngquant_ctx_t *ctx)
{
    ngx_buf_t  *b;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NULL;
    }

    b->pos = ctx->image;
    b->last = ctx->last;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_pngquant_length(r, b);

    return b;
}


static void
ngx_http_pngquant_cleanup(void *data)
{
    gdFree(data);
}


static ngx_buf_t *
ngx_http_pngquant_quantize(ngx_http_request_t *r, ngx_http_pngquant_ctx_t *ctx)
{
    int                       size;
    u_char                    *out;
    ngx_buf_t                 *b;
    gdImagePtr                img;
    ngx_pool_cleanup_t        *cln;
    ngx_http_pngquant_conf_t  *conf;

    img = gdImageCreateFromPngPtr(ctx->length, ctx->image);

    if (img == NULL) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "gdImageCreateFromPngPtr() failed");

        return NULL;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pngquant_module);

    gdImageTrueColorToPaletteSetMethod(img, GD_QUANT_LIQ, conf->speed);
    gdImageTrueColorToPalette(img, conf->dither, conf->colors);

    out = gdImagePngPtr(img, &size);

    gdImageDestroy(img);

    ngx_pfree(r->pool, ctx->image);

    if (out == NULL) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "gdImagePngPtr() failed");

        return NULL;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {

        gdFree(out);

        return NULL;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    if (b == NULL) {

        gdFree(out);

        return NULL;
    }

    cln->handler = ngx_http_pngquant_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_pngquant_length(r, b);
    ngx_http_weak_etag(r);

    return b;
}


static ngx_buf_t *
ngx_http_pngquant_process(ngx_http_request_t *r)
{
    ngx_http_pngquant_ctx_t   *ctx;
    ngx_http_pngquant_conf_t  *conf;

    r->connection->buffered &= ~NGX_HTTP_PNGQUANT_BUFFERED;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pngquant_module);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pngquant_module);

    if (conf->quantize) {

        return ngx_http_pngquant_quantize(r, ctx);
    }

    return ngx_http_pngquant_asis(r, ctx);
}


static ngx_int_t
ngx_http_pngquant_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                 rc;
    ngx_str_t                 *ct;
    ngx_chain_t               out;
    ngx_http_pngquant_ctx_t   *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pngquant");

    if (in == NULL) {

        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pngquant_module);

    if (ctx == NULL) {

        return ngx_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case NGX_HTTP_PNGQUANT_START:

        if (NGX_OK != ngx_http_pngquant_is_png(r, in)) {

            return ngx_http_filter_finalize_request(r,
                &ngx_http_pngquant_module,
                NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* override content type */

        ct = &ngx_http_pngquant_content_type[0];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        ctx->phase = NGX_HTTP_PNGQUANT_READ;

        /* fall through */

    case NGX_HTTP_PNGQUANT_READ:

        rc = ngx_http_pngquant_read(r, in);

        if (rc == NGX_AGAIN) {

            return NGX_OK;
        }

        if (rc == NGX_ERROR) {

            return ngx_http_filter_finalize_request(r,
                &ngx_http_pngquant_module,
                NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case NGX_HTTP_PNGQUANT_PROCESS:

        out.buf = ngx_http_pngquant_process(r);

        if (out.buf == NULL) {

            return ngx_http_filter_finalize_request(r,
                &ngx_http_pngquant_module,
                NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = NGX_HTTP_PNGQUANT_PASS;

        return ngx_http_pngquant_send(r, ctx, &out);

    case NGX_HTTP_PNGQUANT_PASS:

        return ngx_http_next_body_filter(r, in);

    case NGX_HTTP_PNGQUANT_DONE:
    default:

        rc = ngx_http_next_body_filter(r, NULL);

        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
}


static void *
ngx_http_pngquant_create_conf(ngx_conf_t *cf)
{
    ngx_http_pngquant_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pngquant_conf_t));

    if (conf == NULL) {

        return NULL;
    }

    conf->quantize = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->dither = NGX_CONF_UNSET;
    conf->colors = NGX_CONF_UNSET_UINT;
    conf->speed = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_pngquant_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pngquant_conf_t *prev = parent;
    ngx_http_pngquant_conf_t *conf = child;

    ngx_conf_merge_value(conf->quantize, prev->quantize, 0);

    ngx_conf_merge_value(conf->dither, prev->dither, 1);

    ngx_conf_merge_uint_value(conf->colors, prev->colors, 256);

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);

    ngx_conf_merge_uint_value(conf->speed, prev->speed, 0);

    if (conf->colors < 1) {

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pngquant_colors must be equal or more than 1");

        return NGX_CONF_ERROR;
    }

    if (conf->colors > 256) {

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pngquant_colors must be equal or less than 256");

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_pngquant_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_pngquant_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_pngquant_body_filter;

    return NGX_OK;
}