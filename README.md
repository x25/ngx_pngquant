Module ngx_pngquant
============

The ``ngx_pngquant`` module is a filter for lossy compression of PNG images.

## Configuration

```nginx
server {

    set $store_path /tmp/pngquant;

    root /var/www;

    location ~ \.png$ {
        root $store_path;
        try_files $uri @pngquant;
    }

    location @pngquant {
        pngquant on;

        pngquant_buffer_size 1M;
        pngquant_colors 256;
        pngquant_dither on;
        pngquant_speed 1;

        pngquant_store $store_path$uri;
        pngquant_store_access user:rw group:rw all:r;
    }
}
```

## How to build

Install module dependencies:

**Ubuntu or Debian**

```sh
sudo apt-get install build-essential libgd-dev
```

**RedHat, CentOS, or Fedora**

```sh
sudo yum install gcc-c++ gd-devel pcre-devel make
```

Download ``ngx_pngquant`` and install ``libimagequant`` submodule:

```sh
cd
git clone https://github.com/x25/ngx_pngquant
cd ngx_pngquant
git submodule update --init
```

Download and build **nginx**/**openresty**/**tengine** with support for ``ngx_pngquant``:

```sh
cd
# check http://nginx.org/en/download.html for the latest version
wget http://nginx.org/download/nginx-1.6.2.tar.gz
tar -xvzf nginx-1.6.2.tar.gz
cd nginx-1.6.2/
./configure --prefix=/tmp/nginx --add-module=$HOME/ngx_pngquant
make
sudo make install
```

If you want to have debug logs available:

```sh
./configure --prefix=/tmp/nginx --add-module=$HOME/ngx_pngquant --with-debug
```

Start nginx with pngquant module:

```sh
/tmp/nginx/sbin/nginx -c /path/to/nginx.conf
```

## Directives

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant</strong> <i>on | off</i>;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant off;</code></td></tr>
<tr><th>Context:</th><td><code>location</code></td></tr>
</table>

Turns on/off module processing in a surrounding location. 

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_buffer_size</strong> <i>size</i>;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_buffer_size 1M;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

Sets the maximum size of the buffer used for reading images. When the size is exceeded the server returns error **415 (Unsupported Media Type)**.

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_colors</strong> <i>colors</i>;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_colors 256;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

Sets the maximum number of palette entries in images.

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_dither</strong> <i>on | off</i>;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_dither on;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

If dither is set, the image will be dithered to approximate colors better, at the expense of some obvious "speckling."

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_speed</strong> <i>speed</i>;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_speed 0;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

Speed is from 1 (highest quality) to 10 (fastest). Speed 0 selects library-specific default (recommended).

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_store</strong> <i>string<i>;</code></td></tr>
<tr><th>Default:</th><td><code>none</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

Enables saving of processed images to a disk. The file name can be set explicitly using the string with variables: 

```
pngquant_store /data/www$uri;
```

An example of caching:

```nginx
server {
    root /var/www;

    location ~ \.png$ {
        root /tmp/pngquant;
        try_files $uri @pngquant;
    }

    location @pngquant {
        pngquant on;
        pngquant_store /tmp/pngquant$uri;
    }
}
```

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_temp_path</strong> <i>path [level1] [level2] [level3]</i>;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_temp_path /tmp 1 2;</code></td></tr>
<tr><th>Context:</th><td><code>http</code></td></tr>
</table>

Sets temporary area where files are stored before they are moved to ``pngquant_store`` area.

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_store_access</strong> <i>users:permissions ...</i>;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_store_access user:rw;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

Sets access permissions for newly created files and directories, e.g.: 

```
pngquant_store_access user:rw group:rw all:r;
```

If any ``group`` or ``all`` access permissions are specified then user permissions may be omitted: 

```
pngquant_store_access group:rw all:r;
```

## Status

This module is experimental and it's compatible with following web servers:

- nginx 1.6.x (tested with 1.6.2).
- nginx 1.7.x (tested with 1.7.9).

- openresty 1.7.x (tested with 1.7.7.1).
- tengine 2.1.x (tested with 2.1.0).
