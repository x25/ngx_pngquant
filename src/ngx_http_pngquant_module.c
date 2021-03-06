/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Kornel Lesiński (libimagequant)
 * Copyright (C) Thomas G. Lane. (libgd)
 * Copyright (C) x25 <job@x25.ru>
 */

/*
 * Based on nginx/ngx_http_image_filter_module.c
 */


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
    ngx_http_complex_value_t    *store;
    ngx_uint_t                   store_access;
    ngx_path_t                  *temp_path;
} ngx_http_pngquant_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;
    size_t                       length;
    ngx_uint_t                   phase;
} ngx_http_pngquant_ctx_t;


ngx_module_t  ngx_http_pngquant_module;

static ngx_int_t ngx_http_pngquant_header_filter(ngx_http_request_t *r);
static void *ngx_http_pngquant_create_conf(ngx_conf_t *cf);
static char *ngx_http_pngquant_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_pngquant_init(ngx_conf_t *cf);
static char *
ngx_http_pngquant_store_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


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

    { ngx_string("pngquant_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_pngquant_store_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pngquant_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, temp_path),
      NULL },

    { ngx_string("pngquant_store_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pngquant_conf_t, store_access),
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


/**
 * Based on libgd/gd_topal.c
 */
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


/**
 * Based on libgd/gd_topal.c
 */
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


static ngx_buf_t *
ngx_http_pngquant_quantize(ngx_http_request_t *r, ngx_http_pngquant_ctx_t *ctx)
{
    u_char                    *out;
    ngx_buf_t                 *b;
    ngx_pool_cleanup_t        *cln;
    ngx_http_pngquant_conf_t  *conf;
    gdImagePtr                 img;
    int                        size;

    ngx_int_t                  rc;
    ngx_temp_file_t           *tf;
    ssize_t                    n;
    ngx_ext_rename_file_t      ext;
    ngx_str_t                  dest;
    ngx_str_t                  value;


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

    if (conf->store) {

        if(ngx_http_complex_value(r, conf->store, &value) != NGX_OK) {

            goto failed;
        }

        dest.len = value.len + 1;
        dest.data = ngx_pnalloc(r->pool, dest.len);

        if (dest.data == NULL) {

            goto failed;
        }

        ngx_memzero(dest.data, dest.len);
        ngx_memcpy(dest.data, value.data, value.len);

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pngquant_store (%s)", dest.data);

        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));

        if (tf == NULL) {

            goto failed;
        }

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = conf->temp_path;
        tf->pool = r->pool;
        tf->persistent = 1;
        rc = ngx_create_temp_file(&tf->file, tf->path, tf->pool, tf->persistent,
                                  tf->clean, tf->access);

        if (rc != NGX_OK) {

            goto failed;
        }

        n = ngx_write_fd(tf->file.fd, out, size);

        if (n == NGX_FILE_ERROR) {

            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_write_fd_n " \"%s\" failed", tf->file.name.data);

            goto failed;
        }

        if ((int) n != size) {

            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_write_fd_n " has written only %z of %uz bytes",
                          n, size);

            goto failed;
        }

        ext.access = conf->store_access;
        ext.path_access = conf->store_access;
        ext.time = -1;
        ext.create_path = 1;
        ext.delete_file = 1;
        ext.log = r->connection->log;

        rc = ngx_ext_rename_file(&tf->file.name, &dest, &ext);

        if (rc != NGX_OK) {

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ngx_ext_rename_file() failed");

            goto failed;
        }
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {

        goto failed;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    if (b == NULL) {

        goto failed;
    }

    cln->handler = ngx_http_pngquant_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_pngquant_length(r, b);

#if defined(nginx_version) && (nginx_version >= 1007003)
    ngx_http_weak_etag(r);
#endif

    return b;

failed:

    gdFree(out);

    return NULL;
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


static void *
ngx_http_pngquant_create_conf(ngx_conf_t *cf)
{
    ngx_http_pngquant_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pngquant_conf_t));

    if (conf == NULL) {

        return NGX_CONF_ERROR;
    }

    /*
     * via ngx_pcalloc():
     * conf->store = NULL;
     * conf->temp_path = NULL;
     */

    conf->enabled = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->dither = NGX_CONF_UNSET;
    conf->colors = NGX_CONF_UNSET_UINT;
    conf->speed = NGX_CONF_UNSET_UINT;
    conf->store = NGX_CONF_UNSET_PTR;
    conf->store_access = NGX_CONF_UNSET_UINT;

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

    if (ngx_conf_merge_path_value(cf, &conf->temp_path, prev->temp_path,
                                  &ngx_http_pngquant_temp_path) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->store, prev->store, NULL);

    ngx_conf_merge_uint_value(conf->store_access,
                              prev->store_access, NGX_FILE_OWNER_ACCESS);

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

static char *
ngx_http_pngquant_store_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_pngquant_conf_t          *pqlc = conf;
    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    pqlc->store = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));

    if(pqlc->store == NULL) {

        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = pqlc->store;

    if(ngx_http_compile_complex_value(&ccv) != NGX_OK) {

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
