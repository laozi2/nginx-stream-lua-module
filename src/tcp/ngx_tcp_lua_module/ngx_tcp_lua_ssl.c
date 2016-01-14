
/*
 * 
 */


//#ifndef DDEBUG
//#define DDEBUG 0
//#endif
//#include "ddebug.h"


#include "ngx_tcp_lua_ssl.h"
#include "ngx_tcp_lua_util.h"
#include "stdio.h"

#if (NGX_TCP_SSL)


static char ngx_tcp_lua_sslctx_udata_metatable_key;

static int ngx_tcp_lua_new_ssl_ctx(lua_State *L);
static int ngx_tcp_lua_set_ssl_protocols(lua_State *L, int table_index, ngx_uint_t *np);
static int ngx_tcp_lua_set_ssl(lua_State *L, ngx_tcp_lua_ssl_ctx_t *ssl_ctx);
static int ngx_tcp_lua_ssl_ctx_destroy(lua_State *L);

static ngx_conf_bitmask_t  ngx_tcp_lua_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_null_string, 0 }
};

void
ngx_tcp_lua_inject_ssl_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_tcp_lua_new_ssl_ctx);
    lua_setfield(L, -2, "new_ssl_ctx");

    /* {{{nlog object metatable */
    lua_pushlightuserdata(L, &ngx_tcp_lua_sslctx_udata_metatable_key);
    lua_createtable(L, 0 /* narr */, 3 /* nrec */);

    //lua_pushcfunction(L, ngx_tcp_lua_nlog_send);
    //lua_setfield(L, -2, "send");

    //lua_pushvalue(L, -1);
    //lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, ngx_tcp_lua_ssl_ctx_destroy);
    lua_setfield(L, -2, "__gc");

    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */
}

/*
{
    ssl_protocols = {
            "SSLv3",
            "TLSv1",
            "TLSv1.1",
            "TLSv1.2",
        },
    ssl_ciphers = "HIGH:!aNULL:!MD5",
    ssl_verify_depth = 1,
    ssl_trusted_certificate = "",
    ssl_crl = "",
}
*/
static int
ngx_tcp_lua_new_ssl_ctx(lua_State *L)
{
    ngx_tcp_lua_ssl_ctx_t      *ssl_ctx;
    ngx_tcp_session_t          *s;
    int value_index;

    s = ngx_tcp_lua_get_session(L);
    if (s != NULL) { //only in init_by_lua
        return luaL_error(L, "only use in init_by_lua");
    }

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting 1 arguments, but got %d",
                lua_gettop(L));
    }
    
    if (0 == lua_istable(L, 1)) {
        return luaL_argerror(L, 1, "bad argument, table expected");
    }
    
    ssl_ctx = lua_newuserdata(L, sizeof(ngx_tcp_lua_ssl_ctx_t));
    if (ssl_ctx == NULL) {
        return luaL_error(L, "lua_newuserdata out of memory");
    }
    memset(ssl_ctx, 0, sizeof(ngx_tcp_lua_ssl_ctx_t));
    
    value_index = 3;
    //ssl_protocols
    lua_getfield(L, 1, "ssl_protocols");
    if (1 == lua_isnil(L, value_index)) {
        //default
        ssl_ctx->ssl_protocols = NGX_SSL_SSLv3|NGX_SSL_TLSv1|NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2;
    }
    else if (0 == lua_istable(L, value_index)) {
        return luaL_argerror(L, 1, "key ssl_protocols must be array, such as {\"TLSv1\", \"TLSv1.1\",\"TLSv1.2\"}");
    }
    else {    
        if (NGX_ERROR == ngx_tcp_lua_set_ssl_protocols(L, value_index, &ssl_ctx->ssl_protocols)) {
            return luaL_argerror(L, 1, "key ssl_protocols error");
        }
    }
    lua_pop(L, 1);
    
    //ssl_ciphers
    lua_getfield(L, 1, "ssl_ciphers");
    if (1 == lua_isnil(L, value_index)) {
        ngx_str_set(&ssl_ctx->ssl_ciphers, "DEFAULT");
    }
    else if (0 == lua_isstring(L, value_index)) {
        return luaL_argerror(L, 1, "key ssl_ciphers must string");
    }
    else {
        ssl_ctx->ssl_ciphers.data = (u_char *) lua_tolstring(L, value_index, &ssl_ctx->ssl_ciphers.len);
    }
    lua_pop(L, 1);
    
    //ssl_verify_depth
    lua_getfield(L, 1, "ssl_verify_depth");
    if (1 == lua_isnil(L, value_index)) {
        ssl_ctx->ssl_verify_depth = 1;
    }
    else if (0 == lua_isnumber(L, value_index)) {
        return luaL_argerror(L, 1, "key ssl_verify_depth must number");
    }
    else {
        ssl_ctx->ssl_verify_depth = (ngx_uint_t)lua_tonumber(L, value_index);
    }
    lua_pop(L, 1);
    
    //ssl_trusted_certificate
    lua_getfield(L, 1, "ssl_trusted_certificate");
    if (1 == lua_isnil(L, value_index)) {
        ngx_str_set(&ssl_ctx->ssl_trusted_certificate, "");
    }
    else if (0 == lua_isstring(L, value_index)) {
        return luaL_argerror(L, 1, "key ssl_trusted_certificate must string");
    }
    else {
        ssl_ctx->ssl_trusted_certificate.data = (u_char *) lua_tolstring(L, value_index, &ssl_ctx->ssl_trusted_certificate.len);
    }
    lua_pop(L, 1);
    
    //ssl_crl
    lua_getfield(L, 1, "ssl_crl");
    if (1 == lua_isnil(L, value_index)) {
        ngx_str_set(&ssl_ctx->ssl_crl, "");
    }
    else if (0 == lua_isstring(L, value_index)) {
        return luaL_argerror(L, 1, "key ssl_crl must string");
    }
    else {
        ssl_ctx->ssl_crl.data = (u_char *) lua_tolstring(L, value_index, &ssl_ctx->ssl_crl.len);
    }
    lua_pop(L, 1);
    
    if (NGX_ERROR == ngx_tcp_lua_set_ssl(L, ssl_ctx)) {
        return luaL_error(L, "ngx_tcp_lua_set_ssl failed");
    }
    
    lua_pushlightuserdata(L, &ngx_tcp_lua_sslctx_udata_metatable_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);
    
    return 1;
}

static int 
ngx_tcp_lua_set_ssl_protocols(lua_State *L, int table_index, ngx_uint_t *np)
{
    size_t               len,i;
    u_char              *value;
    size_t               value_len;
    int                  m;
    ngx_conf_bitmask_t  *mask;
    
    len = lua_objlen(L, table_index);
    if (len <= 0 || len > 20) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0, "ngx_tcp_lua_set_ssl_protocols len %d <0 or >=20", len);
        return NGX_ERROR;
    }
    
    mask = ngx_tcp_lua_ssl_protocols;
    
    for (i = 1; i <= len; i++) {
        lua_rawgeti(L, table_index, i);
        if (0 == lua_isstring(L, -1)) {
            //log
            return NGX_ERROR;
        }
        
        value = (u_char *) lua_tolstring(L, -1, &value_len);
        
        for (m = 0; ngx_tcp_lua_ssl_protocols[m].name.len != 0; m++) {

            if (mask[m].name.len != value_len
                || ngx_strcasecmp(mask[m].name.data, value) != 0)
            {
                continue;
            }

            if (*np & mask[m].mask) {
                //ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                //                   "duplicate value \"%s\"", value[i].data);
                ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0, "ngx_tcp_lua_set_ssl_protocols duplicate value \"%s\"", value);

                return NGX_ERROR;
            } else {
                *np |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            //ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            //                   "invalid value \"%s\"", value[i].data);
            //
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0, "ngx_tcp_lua_set_ssl_protocols invalid value \"%s\"", value);

            return NGX_ERROR;
        }
        
        lua_pop(L, 1);
    }
    
    return NGX_OK;
}

static int
ngx_tcp_lua_set_ssl(lua_State *L, ngx_tcp_lua_ssl_ctx_t *ssl_ctx)
{
    ngx_conf_t cf;
    cf.cycle = (ngx_cycle_t*)ngx_cycle;

    //use ngx_cycle pool,log  -----but, something wrong when reload, so use lua memory
    //ssl_ctx->ssl = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_ssl_t));
    //if (ssl_ctx->ssl == NULL) {
    //    return NGX_ERROR;
    //}

    ssl_ctx->ssl.log = ngx_cycle->log;

    if (ngx_ssl_create(&ssl_ctx->ssl, ssl_ctx->ssl_protocols, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (SSL_CTX_set_cipher_list(ssl_ctx->ssl.ctx,
                                (const char *) ssl_ctx->ssl_ciphers.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &ssl_ctx->ssl_ciphers);

        return NGX_ERROR;
    }

    if (ssl_ctx->ssl_trusted_certificate.len) {

        if (ngx_ssl_trusted_certificate(&cf, &ssl_ctx->ssl,
                                        &ssl_ctx->ssl_trusted_certificate,
                                        ssl_ctx->ssl_verify_depth)
            != NGX_OK) {
            return NGX_ERROR;
        }
    }

    //dd("ssl crl: %.*s", (int) llcf->ssl_crl.len, llcf->ssl_crl.data);

    if (ngx_ssl_crl(&cf, &ssl_ctx->ssl, &ssl_ctx->ssl_crl) != NGX_OK) {
        return NGX_ERROR;
    }
    //ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0, "ngx_tcp_lua_set_ssl ssl_ctx (%P)(%P)(%P)",ssl_ctx, ssl_ctx->ssl,ssl_ctx->ssl.ctx);

    return NGX_OK;
}


static int
ngx_tcp_lua_ssl_ctx_destroy(lua_State *L)
{
    ngx_tcp_lua_ssl_ctx_t      *ssl_ctx;

    ssl_ctx = lua_touserdata(L, 1);

    //ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0, "ngx_tcp_lua_ssl_ctx_destroy (%P)(%P)(%P)", ssl_ctx,ssl_ctx->ssl,ssl_ctx->ssl.ctx);
    if (ssl_ctx->ssl.ctx) {
        SSL_CTX_free(ssl_ctx->ssl.ctx);
    }

    return 0;
}


#endif /* NGX_TCP_SSL */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
