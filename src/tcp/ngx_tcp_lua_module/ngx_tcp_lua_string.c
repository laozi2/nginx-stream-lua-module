
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


//#ifndef DDEBUG
//#define DDEBUG 0
//#endif
//#include "ddebug.h"


#include "ngx_tcp_lua_string.h"
#include "ngx_tcp_lua_util.h"
//#include "ngx_tcp_lua_args.h"
#include "ngx_crc32.h"

#if NGX_HAVE_SHA1
#include "ngx_sha1.h"
#endif

#include "ngx_md5.h"

#if (NGX_OPENSSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif


#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif


static int ngx_tcp_lua_ngx_md5(lua_State *L);
static int ngx_tcp_lua_ngx_md5_bin(lua_State *L);

#if (NGX_HAVE_SHA1)
static int ngx_tcp_lua_ngx_sha1_bin(lua_State *L);
#endif

static int ngx_tcp_lua_ngx_decode_base64(lua_State *L);
static int ngx_tcp_lua_ngx_encode_base64(lua_State *L);
static int ngx_tcp_lua_ngx_crc32_short(lua_State *L);
static int ngx_tcp_lua_ngx_crc32_long(lua_State *L);
#if (NGX_OPENSSL)
static int ngx_tcp_lua_ngx_hmac_sha1(lua_State *L);
#endif


void
ngx_tcp_lua_inject_string_api(lua_State *L)
{

    lua_pushcfunction(L, ngx_tcp_lua_ngx_decode_base64);
    lua_setfield(L, -2, "decode_base64");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_encode_base64);
    lua_setfield(L, -2, "encode_base64");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_md5_bin);
    lua_setfield(L, -2, "md5_bin");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_md5);
    lua_setfield(L, -2, "md5");

#if (NGX_HAVE_SHA1)
    lua_pushcfunction(L, ngx_tcp_lua_ngx_sha1_bin);
    lua_setfield(L, -2, "sha1_bin");
#endif

    lua_pushcfunction(L, ngx_tcp_lua_ngx_crc32_short);
    lua_setfield(L, -2, "crc32_short");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_crc32_long);
    lua_setfield(L, -2, "crc32_long");

#if (NGX_OPENSSL)
    lua_pushcfunction(L, ngx_tcp_lua_ngx_hmac_sha1);
    lua_setfield(L, -2, "hmac_sha1");
#endif
}


static int
ngx_tcp_lua_ngx_md5(lua_State *L)
{
    u_char                  *src;
    size_t                   slen;

    ngx_md5_t                md5;
    u_char                   md5_buf[MD5_DIGEST_LENGTH];
    u_char                   hex_buf[2 * sizeof(md5_buf)];

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }

    if (lua_isnil(L, 1)) {
        src = (u_char *) "";
        slen = 0;

    } else {
        src = (u_char *) luaL_checklstring(L, 1, &slen);
    }

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, src, slen);
    ngx_md5_final(md5_buf, &md5);

    ngx_hex_dump(hex_buf, md5_buf, sizeof(md5_buf));

    lua_pushlstring(L, (char *) hex_buf, sizeof(hex_buf));

    return 1;
}


static int
ngx_tcp_lua_ngx_md5_bin(lua_State *L)
{
    u_char                  *src;
    size_t                   slen;

    ngx_md5_t                md5;
    u_char                   md5_buf[MD5_DIGEST_LENGTH];

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }

    if (lua_isnil(L, 1)) {
        src     = (u_char *) "";
        slen    = 0;

    } else {
        src = (u_char *) luaL_checklstring(L, 1, &slen);
    }

    dd("slen: %d", (int) slen);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, src, slen);
    ngx_md5_final(md5_buf, &md5);

    lua_pushlstring(L, (char *) md5_buf, sizeof(md5_buf));

    return 1;
}


#if (NGX_HAVE_SHA1)
static int
ngx_tcp_lua_ngx_sha1_bin(lua_State *L)
{
    u_char                  *src;
    size_t                   slen;

    ngx_sha1_t               sha;
    u_char                   sha_buf[SHA_DIGEST_LENGTH];

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }

    if (lua_isnil(L, 1)) {
        src     = (u_char *) "";
        slen    = 0;

    } else {
        src = (u_char *) luaL_checklstring(L, 1, &slen);
    }

    dd("slen: %d", (int) slen);

    ngx_sha1_init(&sha);
    ngx_sha1_update(&sha, src, slen);
    ngx_sha1_final(sha_buf, &sha);

    lua_pushlstring(L, (char *) sha_buf, sizeof(sha_buf));

    return 1;
}
#endif


static int
ngx_tcp_lua_ngx_decode_base64(lua_State *L)
{
    ngx_str_t                p, src;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }

    if (lua_type(L, 1) != LUA_TSTRING) {
        return luaL_error(L, "string argument only");
    }

    src.data = (u_char *) luaL_checklstring(L, 1, &src.len);

    p.len = ngx_base64_decoded_length(src.len);

    p.data = lua_newuserdata(L, p.len);

    if (ngx_decode_base64(&p, &src) == NGX_OK) {
        lua_pushlstring(L, (char *) p.data, p.len);

    } else {
        lua_pushnil(L);
    }

    return 1;
}


static int
ngx_tcp_lua_ngx_encode_base64(lua_State *L)
{
    ngx_str_t                p, src;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }

    if (lua_isnil(L, 1)) {
        src.data = (u_char *) "";
        src.len = 0;

    } else {
        src.data = (u_char *) luaL_checklstring(L, 1, &src.len);
    }

    p.len = ngx_base64_encoded_length(src.len);

    p.data = lua_newuserdata(L, p.len);

    ngx_encode_base64(&p, &src);

    lua_pushlstring(L, (char *) p.data, p.len);

    return 1;
}


static int
ngx_tcp_lua_ngx_crc32_short(lua_State *L)
{
    u_char                  *p;
    size_t                   len;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument, but got %d",
                lua_gettop(L));
    }

    p = (u_char *) luaL_checklstring(L, 1, &len);

    lua_pushnumber(L, (lua_Number) ngx_crc32_short(p, len));
    return 1;
}


static int
ngx_tcp_lua_ngx_crc32_long(lua_State *L)
{
    u_char                  *p;
    size_t                   len;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument, but got %d",
                          lua_gettop(L));
    }

    p = (u_char *) luaL_checklstring(L, 1, &len);

    lua_pushnumber(L, (lua_Number) ngx_crc32_long(p, len));
    return 1;
}


#if (NGX_OPENSSL)
static int
ngx_tcp_lua_ngx_hmac_sha1(lua_State *L)
{
    u_char                  *sec, *sts;
    size_t                   lsec, lsts;
    unsigned int             md_len;
    unsigned char            md[EVP_MAX_MD_SIZE];
    const EVP_MD            *evp_md;

    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting one argument, but got %d",
                          lua_gettop(L));
    }

    sec = (u_char *) luaL_checklstring(L, 1, &lsec);
    sts = (u_char *) luaL_checklstring(L, 2, &lsts);

    evp_md = EVP_sha1();

    HMAC(evp_md, sec, lsec, sts, lsts, md, &md_len);

    lua_pushlstring(L, (char *) md, md_len);

    return 1;
}
#endif

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
