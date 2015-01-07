Module ngx_pngquant
============

The ``ngx_pngquant`` module is a filter for lossy compression of PNG images. 

**Status: dev (not ready for production use!)**

## Example Configuration

```nginx
location ~ \.png$ {
    pngquant on;
    pngquant_buffer_size 1M;
    pngquant_colors 256;
    pngquant_dither on;
    pngquant_speed 1;
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
sudo yum install gcc-c++ gd-devel make
```

Download `ngx_pngquant` and install [libimagequant](https://github.com/pornel/pngquant) submodule:

```sh
cd
git clone https://github.com/x25/ngx_pngquant
cd ngx_pngquant
git submodule update --init
```

Download and build **nginx**/**openresty** with support for ``ngx_pngquant``:

```sh
cd
# check http://nginx.org/en/download.html for the latest version
wget http://nginx.org/download/nginx-1.6.2.tar.gz
tar -xvzf nginx-1.6.2.tar.gz
cd nginx-1.6.2/
./configure --add-module=$HOME/ngx_pngquant
make
sudo make install
```

## Directives

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant</strong> on | off;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant off;</code></td></tr>
<tr><th>Context:</th><td><code>location</code></td></tr>
</table>

Turns on/off module processing in a surrounding location. 

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_buffer_size</strong> size;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_buffer_size 1M;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

Sets the maximum size of the buffer used for reading images. When the size is exceeded the server returns error 415 (Unsupported Media Type).

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_colors</strong> colors;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_colors 256;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

Sets the maximum number of palette entries in images.

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_dither</strong> on | off;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_dither on;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

If dither is set, the image will be dithered to approximate colors better, at the expense of some obvious "speckling."

---

<table cellspacing="0">
<tr><th>Syntax:</th><td><code><strong>pngquant_speed</strong> speed;</code></td></tr>
<tr><th>Default:</th><td><code>pngquant_speed 0;</code></td></tr>
<tr><th>Context:</th><td><code>http</code>, <code>server</code>, <code>location</code></td></tr>
</table>

Speed is from 1 (highest quality) to 10 (fastest). Speed 0 selects library-specific default (recommended).
