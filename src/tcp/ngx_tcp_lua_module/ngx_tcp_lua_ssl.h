
/*
 * 
 */


#ifndef _NGX_TCP_LUA_SSL_H_INCLUDED_
#define _NGX_TCP_LUA_SSL_H_INCLUDED_


#include "ngx_tcp_lua_common.h"


#if (NGX_TCP_SSL)

typedef struct {
    ngx_ssl_t               ssl;  /* shared by SSL cosockets */
    ngx_uint_t              ssl_protocols;
    ngx_str_t               ssl_ciphers;
    ngx_uint_t              ssl_verify_depth;
    ngx_str_t               ssl_trusted_certificate;
    ngx_str_t               ssl_crl;
} ngx_tcp_lua_ssl_ctx_t;

void ngx_tcp_lua_inject_ssl_api(lua_State *L);
#endif


#endif /* _NGX_TCP_LUA_SSL_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
