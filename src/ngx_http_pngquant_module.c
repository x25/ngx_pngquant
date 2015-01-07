/*
* Copyright (C) Igor Sysoev
* Copyright (C) Nginx, Inc.
* Copyright (C) Kornel Lesiński (libimagequant)
* Copyright (C) FRiCKLE <info@frickle.com> (ngx_slowfs_cache)
* Copyright (C) Thomas G. Lane. (libgd)
* Copyright (C) x25 <job@x25.ru>
*/

//#if (NGX_HTTP_CACHE)

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <gd.h>

#include "../deps/pngquant/lib/libimagequant.h"


#define NGX_HTTP_PNGQUANT_START     0
#define NGX_HTTP_PNGQUANT_READ      1
#define NGX_HTTP_PNGQUANT_PROCESS   2
#define NGX_HTTP_PNGQUANT_PASS      3
#define NGX_HTTP_PNGQUANT_DONE      4


#define NGX_HTTP_PNGQUANT_BUFFERED  0x08


typedef struct {
    ngx_flag_t                   enabled;
    size_t                       buffer_size;
    ngx_flag_t                   dither;
    ngx_uint_t                   colors;
    ngx_uint_t                   speed;
    ngx_shm_zone_t              *cache;
    ngx_array_t                 *cache_valid;
    ngx_http_complex_value_t     cache_key;
    ngx_path_t                  *temp_path;
} ngx_http_pngquant_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;
    size_t                       length;
    ngx_uint_t                   phase;
    ngx_uint_t                   cache_status;
} ngx_http_pngquant_ctx_t;


ngx_module_t  ngx_http_pngquant_module;

static ngx_int_t ngx_http_pngquant_header_filter(ngx_http_request_t *r);
static void *ngx_http_pngquant_create_conf(ngx_conf_t *cf);
static char *ngx_http_pngquant_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_pngquant_init(ngx_conf_t *cf);
char * ngx_http_pngquant_cache_conf(ngx_conf_t *ngx_cf, ngx_command_t *cmd,
    void *conf);
char * ngx_http_pngquant_cache_key_conf(ngx_conf_t *ngx_cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_pngquant_commands[] = {

    { ngx_string("pngquant"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, enabled),
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

    { ngx_string("pngquant_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_pngquant_cache_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pngquant_cache_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_pngquant_cache_key_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pngquant_cache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, cache_valid),
      NULL },

    { ngx_string("pngquant_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_file_cache_set_slot,
      0,
      0,
      &ngx_http_pngquant_module },

    { ngx_string("pngquant_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, temp_path),
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


static ngx_path_init_t ngx_http_pngquant_temp_path = {
    ngx_string("/tmp"), { 1, 2, 0 }
};


static ngx_str_t  ngx_http_pngquant_content_type[] = {
    ngx_string("image/png")
};


char *
ngx_http_pngquant_cache_conf(ngx_conf_t *ngx_cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = ngx_cf->args->elts;

    ngx_http_pngquant_conf_t *cf = conf;

    if (cf->cache != NGX_CONF_UNSET_PTR && cf->cache != NULL) {

        return "duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {

        cf->enabled = 0;
        cf->cache = NULL;

        return NGX_CONF_OK;
    }

    cf->cache = ngx_shared_memory_add(ngx_cf, &value[1], 0,
        &ngx_http_pngquant_module);

    if (cf->cache == NULL) {

        return NGX_CONF_ERROR;
    }

    cf->enabled = 1;

    return NGX_CONF_OK;
}


char *
ngx_http_pngquant_cache_key_conf(ngx_conf_t *ngx_cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t *value = ngx_cf->args->elts;
    ngx_http_pngquant_conf_t *cf = conf;
    ngx_http_compile_complex_value_t ccv;

    if (cf->cache_key.value.len) {

        return "duplicate";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = ngx_cf;
    ccv.value = &value[1];
    ccv.complex_value = &cf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
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
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_pngquant_ctx_t  *ctx;
    size_t                    size, rest;

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


static void
ngx_pngquant_free_true_color_image_data(gdImagePtr oim)
{
    int i;
    oim->trueColor = 0;
    /* Junk the truecolor pixels */
    for (i = 0; i < oim->sy; i++) {
            gdFree (oim->tpixels[i]);
    }
    free (oim->tpixels);
    oim->tpixels = 0;
}


static void
ngx_pngquant_convert_gd_pixel_to_rgba(liq_color output_row[], int y, int width,
    void *userinfo)
{
    gdImagePtr oim = userinfo;
    int x;

    for(x = 0; x < width; x++) {

        output_row[x].r = gdTrueColorGetRed(oim->tpixels[y][x]) * 255/gdRedMax;
        output_row[x].g = gdTrueColorGetGreen(oim->tpixels[y][x]) * 255/gdGreenMax;
        output_row[x].b = gdTrueColorGetBlue(oim->tpixels[y][x]) * 255/gdBlueMax;

        int alpha = gdTrueColorGetAlpha(oim->tpixels[y][x]);

        if (gdAlphaOpaque < gdAlphaTransparent) {

            alpha = gdAlphaTransparent - alpha;
        }

        output_row[x].a = alpha * 255/gdAlphaMax;
    }
}


static int
ngx_pngquant_gd_image(gdImagePtr oim, int dither, int colorsWanted, int speed)
{
    int i;

    int maxColors = gdMaxColors;

    if (!oim->trueColor) {

        return 1;
    }

    /* If we have a transparent color (the alphaless mode of transparency), we
     * must reserve a palette entry for it at the end of the palette. */
    if (oim->transparent >= 0) {

        maxColors--;
    }

    if (colorsWanted > maxColors) {

        colorsWanted = maxColors;
    }

    oim->pixels = calloc(sizeof (unsigned char *), oim->sy);

    if (!oim->pixels) {
            /* No can do */
        goto outOfMemory;
    }

    for (i = 0; (i < oim->sy); i++) {

        oim->pixels[i] = (unsigned char *) calloc(sizeof (unsigned char *),
                                                  oim->sx);

        if (!oim->pixels[i]) {
                goto outOfMemory;
        }
    }

    liq_attr *attr = liq_attr_create_with_allocator(malloc, gdFree);

    liq_image *image;
    liq_result *remap;
    int remapped_ok = 0;

    liq_set_max_colors(attr, colorsWanted);

    /* by default make it fast to match speed of previous implementation */
    liq_set_speed(attr, speed ? speed : 9);

    if (oim->paletteQuantizationMaxQuality) {

        liq_set_quality(attr,
                        oim->paletteQuantizationMinQuality,
                        oim->paletteQuantizationMaxQuality);
    }

    image = liq_image_create_custom(attr, ngx_pngquant_convert_gd_pixel_to_rgba,
                                    oim, oim->sx, oim->sy, 0);
    remap = liq_quantize_image(attr, image);

    if (!remap) { /* minimum quality not met, leave image unmodified */

        liq_image_destroy(image);
        liq_attr_destroy(attr);

        goto outOfMemory;
    }

    liq_set_dithering_level(remap, dither ? 1 : 0);

    if (LIQ_OK == liq_write_remapped_image_rows(remap, image, oim->pixels)) {

        remapped_ok = 1;

        const liq_palette *pal = liq_get_palette(remap);

        oim->transparent = -1;

        unsigned int icolor;

        for(icolor=0; icolor < pal->count; icolor++) {

            oim->open[icolor] = 0;
            oim->red[icolor] = pal->entries[icolor].r * gdRedMax/255;
            oim->green[icolor] = pal->entries[icolor].g * gdGreenMax/255;
            oim->blue[icolor] = pal->entries[icolor].b * gdBlueMax/255;

            int alpha = pal->entries[icolor].a * gdAlphaMax/255;

            if (gdAlphaOpaque < gdAlphaTransparent) {

                alpha = gdAlphaTransparent - alpha;
            }

            oim->alpha[icolor] = alpha;

            if (oim->transparent == -1 && alpha == gdAlphaTransparent) {

                oim->transparent = icolor;
            }
        }

        oim->colorsTotal = pal->count;
    }

    liq_result_destroy(remap);
    liq_image_destroy(image);
    liq_attr_destroy(attr);

    if (remapped_ok) {

        ngx_pngquant_free_true_color_image_data(oim);

        return 1;
    }

outOfMemory:

    if (oim->trueColor) {

        /* On failure only */
        if (oim->pixels) {

            for (i = 0; i < oim->sy; i++) {

                if (oim->pixels[i]) {
                        gdFree (oim->pixels[i]);
                }
            }

            gdFree (oim->pixels);
        }

        oim->pixels = NULL;
    }

    return 0;
}


/*@TODO*/


static ngx_buf_t *
ngx_http_pngquant_quantize(ngx_http_request_t *r, ngx_http_pngquant_ctx_t *ctx)
{
    u_char                    *out;
    ngx_buf_t                 *b;
    ngx_pool_cleanup_t        *cln;
    ngx_http_pngquant_conf_t  *conf;
    gdImagePtr                 img;
//    time_t                     valid;
    int                        size;

    img = gdImageCreateFromPngPtr(ctx->length, ctx->image);

    if (img == NULL) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "gdImageCreateFromPngPtr() failed");

        return NULL;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pngquant_module);

    /*
     * gdImageTrueColorToPaletteSetMethod(img, GD_QUANT_LIQ, conf->speed);
     * gdImageTrueColorToPalette(img, conf->dither, conf->colors);
     */

    ngx_pngquant_gd_image(img, conf->dither, conf->colors, conf->speed);

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

    /*@TODO*/

    ngx_http_pngquant_length(r, b);
//    ngx_http_weak_etag(r);

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

    if (conf->enabled) {

        return ngx_http_pngquant_quantize(r, ctx);
    }

    return ngx_http_pngquant_asis(r, ctx);
}


static ngx_int_t
ngx_http_pngquant_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_str_t                 *ct;
    ngx_chain_t                out;
    ngx_http_pngquant_ctx_t   *ctx;

    if (in == NULL) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pngquant_body_filter (!in)");

        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pngquant_module);

    if (ctx == NULL) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pngquant_body_filter (!ctx)");

        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "pngquant_body_filter");

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


ngx_int_t
ngx_http_pngquant_cache_send(ngx_http_request_t *r)
{
    ngx_http_pngquant_conf_t  *conf;
//    ngx_http_pngquant_ctx_t   *ctx;

    ngx_http_cache_t *c;

    ngx_str_t *key;
    ngx_int_t rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pngquant_module);
    /*@TODO! ctx = get_ctx(), ctx->cache_status = ...*/

    c = r->cache;

    if (c != NULL) {

        goto skip_alloc;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "pngquant_cache (alloc)");

    c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));

    if (c == NULL) {

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_array_init(&c->keys, r->pool, 1, sizeof(ngx_str_t));

    if (rc != NGX_OK) {

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    key = ngx_array_push(&c->keys);

    if (key == NULL) {

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_complex_value(r, &conf->cache_key, key);

    if (rc != NGX_OK) {

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->cache = c;
    c->body_start = ngx_pagesize;
    c->min_uses = 1;
    c->file_cache = conf->cache->data;
    c->file.log = r->connection->log;
    ngx_http_file_cache_create_key(r);

skip_alloc:
    rc = ngx_http_file_cache_open(r);

    if (rc != NGX_OK) {

        if (rc == NGX_HTTP_CACHE_STALE) {
            /*
            * Revert c->node->updating = 1, we want this to be true only when
            * module is in the process of copying given file.
            */
            ngx_shmtx_lock(&c->file_cache->shpool->mutex);
            c->node->updating = 0;

            c->updating = 0;

            ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "pngquant_cache (stale)");

        } else if (rc == NGX_HTTP_CACHE_UPDATING) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "pngquant_cache (updating)");

        } else {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "pngquant_cache (miss)");
        }

        return NGX_DECLINED;
    }

    r->connection->log->action = "sending cached response to client";

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "pngquant_cache (hit)");

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = c->length - c->body_start;
    r->headers_out.last_modified_time = c->last_modified;

    if (ngx_http_set_content_type(r) != NGX_OK) {

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allow_ranges = 1;

    return ngx_http_cache_send(r);
}


static ngx_int_t
ngx_http_pngquant_header_filter(ngx_http_request_t *r)
{
    off_t                      len;
    ngx_http_pngquant_ctx_t   *ctx;
    ngx_http_pngquant_conf_t  *conf;

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pngquant_header_filter (not_modified)");

        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pngquant_module);

    if (ctx) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pngquant_header_filter (set_ctx)");

        ngx_http_set_ctx(r, NULL, ngx_http_pngquant_module);

        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pngquant_module);

    if (!conf->enabled) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pngquant_header_filter (!enabled)");

        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "pngquant_header_filter");

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


ngx_int_t
ngx_http_pngquant_content_handler(ngx_http_request_t *r)
{
    ngx_http_pngquant_conf_t  *conf;
    ngx_int_t rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pngquant_module);

    if (!conf->enabled || !conf->cache) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pngquant_content_handler (-)");

        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pngquant_content_handler (+)");

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {

        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {

        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {

        return rc;
    }

#if defined(nginx_version) \
    && ((nginx_version < 7066) \
            || ((nginx_version >= 8000) && (nginx_version < 8038)))
    if (r->zero_in_uri) {

        return NGX_DECLINED;
    }
#endif

    rc = ngx_http_pngquant_cache_send(r);

    if (rc == NGX_DECLINED) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pngquant_content_handler (cache_miss)");
    }

    return rc;
}


static void *
ngx_http_pngquant_create_conf(ngx_conf_t *cf)
{
    ngx_http_pngquant_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pngquant_conf_t));

    if (conf == NULL) {

        return NULL;
    }

    /*
     * via ngx_pcalloc():
     * conf->cache_key = NULL;
     * conf->temp_path = NULL;
     */

    conf->enabled = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->dither = NGX_CONF_UNSET;
    conf->colors = NGX_CONF_UNSET_UINT;
    conf->speed = NGX_CONF_UNSET_UINT;
    conf->cache = NGX_CONF_UNSET_PTR;
    conf->cache_valid = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_pngquant_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pngquant_conf_t *prev = parent;
    ngx_http_pngquant_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    ngx_conf_merge_value(conf->dither, prev->dither, 1);

    ngx_conf_merge_uint_value(conf->colors, prev->colors, 256);

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);

    ngx_conf_merge_uint_value(conf->speed, prev->speed, 0);

    ngx_conf_merge_ptr_value(conf->cache, prev->cache, NULL);

    ngx_conf_merge_ptr_value(conf->cache_valid, prev->cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {

        conf->cache_key = prev->cache_key;
    }

    if (ngx_conf_merge_path_value(cf, &conf->temp_path, prev->temp_path,
                                  &ngx_http_pngquant_temp_path) != NGX_OK)
    {

        return NGX_CONF_ERROR;
    }

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

    if (conf->cache && conf->cache->data == NULL) {

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"pngquant_cache\" zone \"%V\" is unknown",
                           &conf->cache->shm.name);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_pngquant_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *conf;

    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&conf->phases[NGX_HTTP_CONTENT_PHASE].handlers);

    if (h == NULL) {

        return NGX_ERROR;
    }

    *h = ngx_http_pngquant_content_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_pngquant_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_pngquant_body_filter;

    return NGX_OK;
}

//#endif /* NGX_HTTP_CACHE */
