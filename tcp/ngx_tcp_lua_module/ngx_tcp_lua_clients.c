
/*

 */

#include "ngx_tcp_lua_util.h"
#include "ngx_tcp_lua_clients.h"
#include "ngx_tcp_lua_req.h"

#define NGX_TCP_LUA_REQ_FT_ERROR        0x0001   //must same define in ngx_tcp_lua_req.c

static int ngx_tcp_lua_ngx_clients_set(lua_State *L);
static int ngx_tcp_lua_ngx_clients_send(lua_State *L);
static int ngx_tcp_lua_ngx_clients_del(lua_State *L);
static int ngx_tcp_lua_ngx_clients_exists(lua_State *L);
static int ngx_tcp_lua_ngx_clients_keys_iter(lua_State *L);

void
ngx_tcp_lua_inject_clients_api(lua_State *L)
{
    /* ngx.clients */

    lua_createtable(L, 0, 5 /* nrec */);

    lua_pushcfunction(L, ngx_tcp_lua_ngx_clients_set);
    lua_setfield(L, -2, "set");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_clients_send);
    lua_setfield(L, -2, "send");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_clients_del);
    lua_setfield(L, -2, "del");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_clients_exists);
    lua_setfield(L, -2, "exists");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_clients_keys_iter);
    lua_setfield(L, -2, "keys_iter");

    lua_setfield(L, -2, "clients");
}

static int 
ngx_tcp_lua_ngx_clients_set(lua_State *L)
{
    ngx_str_t             client_id, *ctx_client_id;
    ngx_tcp_session_t    *s;
    ngx_tcp_lua_ctx_t    *ctx;
    ngx_tcp_lua_client_t *client;

    s = ngx_tcp_lua_get_session(L); 
    if (s == NULL) {
        return luaL_error(L, "no session found");
    }

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }
    luaL_checktype(L, 1, LUA_TSTRING);
    
    client_id.data = (u_char *) lua_tolstring(L, 1, &client_id.len);
    ctx = s->ctx;
    ctx_client_id = &ctx->client_id;
    if (ctx_client_id->data != NULL) {
        if (ngx_strcmp(ctx_client_id->data, client_id.data) == 0) {
            lua_pushnil(L);
            return 1;
        }
        lua_pushliteral(L, "client id already set");
        return 1;
    }
    
    lua_pushlightuserdata(L, &ngx_tcp_lua_clients_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX);  // 1/-2(client_id)->2/-1(table)
    lua_insert(L, 1);  // 1/-2(table)->2/-1(client_id)
    
    client = lua_newuserdata(L, sizeof(ngx_tcp_lua_client_t)); // 1/-3(table)->2/-2(client_id)->3/-1(userdata)
    client->session = s;
    ctx_client_id->data = client_id.data;
    // TODO revise, tx_client_id->data may not remained, see https://www.runoob.com/manual/lua53doc/manual.html#lua_tolstring
    ctx_client_id->len = client_id.len;
    
    lua_settable(L, 1); // 1/-1(table)
    lua_pushnil(L);
    return 1;
}

static int 
ngx_tcp_lua_ngx_clients_exists(lua_State *L)
{
    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }
    luaL_checktype(L, 1, LUA_TSTRING);
    
    lua_pushlightuserdata(L, &ngx_tcp_lua_clients_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_insert(L, 1);
    lua_rawget(L, 1);
    
    lua_pushboolean(L, lua_isuserdata(L, -1));
    return 1;
}

static int 
ngx_tcp_lua_ngx_clients_del(lua_State *L)
{
    ngx_tcp_session_t    *s;
    ngx_tcp_lua_client_t *client;
    ngx_tcp_lua_ctx_t    *ctx;
    
    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }
    luaL_checktype(L, 1, LUA_TSTRING);
    
    lua_pushlightuserdata(L, &ngx_tcp_lua_clients_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushvalue(L, 1); // 1/-3(client_id)->2/-2(table)->3/-1(client_id)
    lua_rawget(L, 2); // 1/-3(client_id)->2/-2(table)->3/-1(userdata)
    client = lua_touserdata(L, -1);
    if (client == NULL) {
        lua_pushliteral(L, "no such userdata");
        return 1;
    }
    s = client->session;
    if (s == NULL) {
        lua_pushliteral(L, "no valid session in userdatas");
        return 1;
    }
    ctx = s->ctx;
    ngx_str_null(&ctx->client_id);
    
    lua_pop(L, 1); // 1/-2(client_id)->2/-1(table)
    lua_insert(L, 1); // 1/-2(table)->2/-1(client_id)
    lua_pushnil(L); // 1/-3(table)->2/-2(client_id)->3/-1(nil)
    lua_settable(L, 1); 
    
    return 0;
}

static int
ngx_tcp_lua_ngx_clients_send(lua_State *L)
{
    u_char                 errstr[NGX_MAX_ERROR_STR];
    u_char                *p;
    const char            *msg;
    size_t                 len;
    ngx_int_t              n;
    ngx_tcp_session_t      *s;
    ngx_tcp_lua_client_t   *client;
    ngx_tcp_lua_ctx_t      *ctx;
    
    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting one argument");
    }
    luaL_checktype(L, 1, LUA_TSTRING); // client_id
    luaL_checktype(L, 2, LUA_TSTRING); // msg
    
    lua_pushlightuserdata(L, &ngx_tcp_lua_clients_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX); // 1/-3(client_id)->2/-2(msg)->3/-1(table)
    lua_pushvalue(L, 1); // 1/-4(client_id)->2/-3(msg)->3/-2(table)->4/-1(client_id)
    lua_rawget(L, -2); // 1/-4(client_id)->2/-3(msg)->3/-2(table)->4/-1(userdata)
    client = lua_touserdata(L, -1);
    if (client == NULL) {
        lua_pushnil(L);
        lua_pushliteral(L, "no such userdata");
        return 2;
    }
    s = client->session;
    if (s == NULL) {
        lua_pushnil(L);
        lua_pushliteral(L, "no valid session in userdatas");
        return 2;
    }
    ctx = s->ctx;
    if (ctx->socket_invalid) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "attempt to send data on a closed/invalid socket");

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    msg = lua_tolstring(L, 2, &len);
    if (len == 0) {
        /* do nothing for empty strings */
        lua_pushnil(L);
        lua_pushliteral(L, "will send nothing");
        return 2;
    }

    n = s->connection->send(s->connection, (u_char*)msg, len);

    if (n > 0) {
        lua_pushnumber(L, (lua_Number) n);
        lua_pushnil(L);
    }
    else if (n == NGX_AGAIN) {
        //lua_pushnumber(L, (lua_Number) 0);
        lua_pushnil(L);
        lua_pushliteral(L, "EAGAIN error");
    }
    else {
         //NGX_ERROR
        ctx->ft_type |= NGX_TCP_LUA_REQ_FT_ERROR;
        ctx->socket_invalid = 1;
        ctx->socket_errno = ngx_socket_errno;

        lua_pushnil(L);
        p = ngx_strerror(ctx->socket_errno, errstr, sizeof(errstr));

        /* for compatibility with LuaSocket */
        ngx_strlow(errstr, errstr, p - errstr);
        lua_pushlstring(L, (char *) errstr, p - errstr);
    }

    return 2;
}


static int 
ngx_tcp_lua_ngx_clients_keys_iter(lua_State *L)
{
    lua_pushliteral(L, "not implement");
    return 1;
}


void
ngx_tcp_lua_clients_cleanup(lua_State *L, void *data)
{
    ngx_tcp_lua_ctx_t          *ctx;
    
    ctx = data;
    if (ctx->client_id.data == NULL) {
        return;
    }

    lua_pushlightuserdata(L, &ngx_tcp_lua_clients_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushlstring(L, (const char*)ctx->client_id.data, ctx->client_id.len);
    lua_pushnil(L); // 1/-3(table)->2/-2(client_id)->3/-1(nil)
    lua_settable(L, 1);
}