
#include "ngx_tcp_lua_log.h"
#include "ngx_tcp_lua_util.h"

static int ngx_tcp_lua_print(lua_State *L);
static int ngx_tcp_lua_ngx_log(lua_State *L);
static int ngx_tcp_lua_ngx_nlog(lua_State *L);
static int ngx_tcp_lua_nlog_send(lua_State *L);
static int ngx_tcp_lua_nlog_destroy(lua_State *L);

static char ngx_tcp_lua_nlog_udata_metatable_key;


static int log_wrapper(ngx_tcp_session_t *s, const char *ident,
        ngx_uint_t level, lua_State *L);

static void ngx_tcp_lua_inject_log_consts(lua_State *L);

void
ngx_tcp_lua_inject_log_api(lua_State *L)
{
    ngx_tcp_lua_inject_log_consts(L);

    lua_pushcfunction(L, ngx_tcp_lua_ngx_log);
    lua_setfield(L, -2, "log");

    lua_pushcfunction(L, ngx_tcp_lua_print);
    lua_setglobal(L, "print");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_nlog);
    lua_setfield(L, -2, "nlog");

    /* {{{nlog object metatable */
    lua_pushlightuserdata(L, &ngx_tcp_lua_nlog_udata_metatable_key);
    lua_createtable(L, 0 /* narr */, 3 /* nrec */);

    lua_pushcfunction(L, ngx_tcp_lua_nlog_send);
    lua_setfield(L, -2, "send");

    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, ngx_tcp_lua_nlog_destroy);
    lua_setfield(L, -2, "__gc");

    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */
}


static void
ngx_tcp_lua_inject_log_consts(lua_State *L)
{
    /* {{{ nginx log level constants */
    lua_pushinteger(L, NGX_LOG_STDERR);
    lua_setfield(L, -2, "STDERR");

    lua_pushinteger(L, NGX_LOG_EMERG);
    lua_setfield(L, -2, "EMERG");

    lua_pushinteger(L, NGX_LOG_ALERT);
    lua_setfield(L, -2, "ALERT");

    lua_pushinteger(L, NGX_LOG_CRIT);
    lua_setfield(L, -2, "CRIT");

    lua_pushinteger(L, NGX_LOG_ERR);
    lua_setfield(L, -2, "ERR");

    lua_pushinteger(L, NGX_LOG_WARN);
    lua_setfield(L, -2, "WARN");

    lua_pushinteger(L, NGX_LOG_NOTICE);
    lua_setfield(L, -2, "NOTICE");

    lua_pushinteger(L, NGX_LOG_INFO);
    lua_setfield(L, -2, "INFO");

    lua_pushinteger(L, NGX_LOG_DEBUG);
    lua_setfield(L, -2, "DEBUG");
    /* }}} */
}


/**
 * Wrapper of nginx log functionality. Take a log level param and varargs of
 * log message params.
 *
 * @param L Lua state pointer
 * @retval always 0 (don't return values to Lua)
 * */
int
ngx_tcp_lua_ngx_log(lua_State *L)
{
    ngx_tcp_session_t          *s;
    const char                 *msg;

    s = ngx_tcp_lua_get_session(L); 
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    if (s && s->connection && s->connection->log) {
        int level = luaL_checkint(L, 1);
        if (level < NGX_LOG_STDERR || level > NGX_LOG_DEBUG) {
            msg = lua_pushfstring(L, "bad log level: %d", level);
            return luaL_argerror(L, 1, msg);
        }

        /* remove log-level param from stack */
        lua_remove(L, 1);

        return log_wrapper(s, "[lua] ", (ngx_uint_t) level, L);
    }

    dd("(lua-log) can't output log due to invalid logging context!");

    return 0;
}


/**
 * Override Lua print function, output message to nginx error logs. Equal to
 * ngx.log(ngx.ERR, ...).
 *
 * @param L Lua state pointer
 * @retval always 0 (don't return values to Lua)
 * */
int
ngx_tcp_lua_print(lua_State *L)
{
    ngx_tcp_session_t          *s;

    s = ngx_tcp_lua_get_session(L); 

    if (s && s->connection && s->connection->log) {
        return log_wrapper(s, "[lua] ", NGX_LOG_NOTICE, L);

    } else {
        dd("(lua-print) can't output print content to error log due "
                "to invalid logging context!");
    }

    return 0;
}


static int
log_wrapper(ngx_tcp_session_t *s, const char *ident, ngx_uint_t level,
        lua_State *L)
{
    u_char              *buf;
    u_char              *p, *q;
    ngx_str_t            name;
    int                  nargs, i;
    size_t               size, len;
    size_t               src_len = 0;
    int                  type;
    const char          *msg;
    lua_Debug            ar;
    ngx_buf_t           *b;

    if (level > s->connection->log->log_level) {
        return 0;
    }

    dd("log level: %d", (int)level);
#if 1
    /* add debug info */

    lua_getstack(L, 1, &ar);
    lua_getinfo(L, "Snl", &ar);

    /* get the basename of the Lua source file path, stored in q */
    name.data = (u_char *) ar.short_src;
    if (name.data == NULL) {
        name.len = 0;

    } else {
        p = name.data;
        while (*p != '\0') {
            if (*p == '/' || *p == '\\') {
                name.data = p + 1;
            }
            p++;
        }

        name.len = p - name.data;
    }

#endif

    nargs = lua_gettop(L);

    size = name.len + NGX_INT_T_LEN + sizeof(":: ") - 1;

    if (*ar.namewhat != '\0' && *ar.what == 'L') {
        src_len = ngx_strlen(ar.name);
        size += src_len + sizeof("(): ") - 1;
    }

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                lua_tolstring(L, i, &len);
                size += len;
                break;

            case LUA_TNIL:
                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TLIGHTUSERDATA:
                if (lua_touserdata(L, i) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:
                msg = lua_pushfstring(L, "string, number, boolean, or nil "
                         "expected, got %s", lua_typename(L, type));
                return luaL_argerror(L, i, msg);
        }
    }

    //buf = lua_newuserdata(L, size + 1);
    b = ngx_create_temp_buf(s->pool, size + 1);
    buf = (u_char*)b->pos;

    p = ngx_copy(buf, name.data, name.len);

    *p++ = ':';

    p = ngx_snprintf(p, NGX_INT_T_LEN, "%d",
                     ar.currentline ? ar.currentline : ar.linedefined);

    *p++ = ':'; *p++ = ' ';

    if (*ar.namewhat != '\0' && *ar.what == 'L') {
        p = ngx_copy(p, ar.name, src_len);
        *p++ = '(';
        *p++ = ')';
        *p++ = ':';
        *p++ = ' ';
    }

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                q = (u_char *) lua_tolstring(L, i, &len);
                p = ngx_copy(p, q, len);
                break;

            case LUA_TNIL:
                *p++ = 'n';
                *p++ = 'i';
                *p++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    *p++ = 't';
                    *p++ = 'r';
                    *p++ = 'u';
                    *p++ = 'e';

                } else {
                    *p++ = 'f';
                    *p++ = 'a';
                    *p++ = 'l';
                    *p++ = 's';
                    *p++ = 'e';
                }

                break;

            case LUA_TLIGHTUSERDATA:
                *p++ = 'n';
                *p++ = 'u';
                *p++ = 'l';
                *p++ = 'l';

                break;

            default:
                return luaL_error(L, "impossible to reach here");
        }
    }

    *p++ = '\0';

    if (p - buf > (off_t) (size + 1)) {
        return luaL_error(L, "buffer error: %d > %d", (int) (p - buf),
                          (int) (size + 1));
    }

    ngx_log_error(level, s->connection->log, 0, "%s%s", ident, buf);

    return 0;
}

static int
ngx_tcp_lua_ngx_nlog(lua_State *L)
{
    ngx_tcp_session_t          *ps;
    ngx_socket_t               *u;
    ngx_url_t                   u_l;
    ngx_url_t                   u_r;
    ngx_socket_t                s;
    u_char                     *p;
    size_t                      len;
    int                         reuseaddr;

    ps = ngx_tcp_lua_get_session(L);
    if (ps != NULL) { //only in init_by_lua
        return luaL_error(L, "only use in init_by_lua");
    }

    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting 2 arguments, but got %d",
                lua_gettop(L));
    }

    //check and parse args
    p = (u_char *) luaL_checklstring(L, 1, &len);
    if (p == NULL) {
        return luaL_argerror(L, 1, "bad argument, string expected");
    }

    ngx_memzero(&u_l, sizeof(ngx_url_t));
    u_l.url.data = p;
    u_l.url.len = len;
    u_l.default_port = (in_port_t) 0;
    u_l.no_resolve = 1;

    //use ngx_cycle pool
    if (ngx_parse_url(ngx_cycle->pool, &u_l) != NGX_OK) {
        return luaL_argerror(L, 1, "bad argument, wrong format of ip:port");
    }

    if (u_l.no_port || u_l.family != AF_INET) {
        return luaL_argerror(L, 1, "bad argument, wrong format of ip:port");
    }
    
    p = (u_char *) luaL_checklstring(L, 2, &len);
    if (p == NULL) {
        return luaL_argerror(L, 2, "bad argument, string expected");
    }

    ngx_memzero(&u_r, sizeof(ngx_url_t));
    u_r.url.data = p;
    u_r.url.len = len;
    u_r.default_port = (in_port_t) 0;
    u_r.no_resolve = 1;

    if (ngx_parse_url(ngx_cycle->pool, &u_r) != NGX_OK) {
        return luaL_argerror(L, 2, "bad argument, wrong format of ip:port");
    }
    
    if (u_r.no_port || u_r.family != AF_INET) {
        return luaL_argerror(L, 2, "bad argument, wrong format of ip:port");
    }

    //create socket
    s = ngx_socket(AF_INET, SOCK_DGRAM, 0);

    if (s == -1) {
        return luaL_error(L, "ngx_socket failed");
    }

    if (ngx_nonblocking(s) == -1) {        
        ngx_close_socket(s);
        return luaL_error(L, "ngx_nonblocking failed");
    }

    reuseaddr = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int))
                == -1) {
        ngx_close_socket(s);
        return luaL_error(L, "setsockopt SO_REUSEADDR failed");
    }

    if (bind(s, (struct sockaddr_in*) &u_l.sockaddr, u_l.socklen) == -1) {
        ngx_close_socket(s);
        return luaL_error(L, "bind failed");
    }
    
    if (connect(s, (struct sockaddr_in*) &u_r.sockaddr, u_r.socklen) == -1) {
        ngx_close_socket(s);
        return luaL_error(L, "connect failed");
    }

    u = lua_newuserdata(L, sizeof(ngx_socket_t));
    if (u == NULL) {
        ngx_close_socket(s);
        return luaL_error(L, "out of memory");
    }

    *u = s;

    lua_pushlightuserdata(L, &ngx_tcp_lua_nlog_udata_metatable_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    return 1;
}

static int
ngx_tcp_lua_nlog_send(lua_State *L)
{
    ngx_socket_t      *u;
    ngx_socket_t       s;
    u_char            *p;
    size_t             len;
    int                n;
    
    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting 1 arguments, but got %d",
                lua_gettop(L));
    }
    
    u = lua_touserdata(L, 1);
    if (u == NULL) {
        return luaL_error(L, "wrong nlog object");
    }
    
    s = *u;
    if (s == -1) {
        return luaL_error(L, "uninited nlog object");
    }
    
    p = (u_char *) lua_tolstring(L, 2, &len);
    if (p == NULL || len <= 0) {
        return luaL_error(L, "nlog only send string");
    }
    
    n = send(s, p, len, 0);
    
    lua_pushnumber(L, (lua_Number) n);
    
    return 1;
}

static int
ngx_tcp_lua_nlog_destroy(lua_State *L)
{
    ngx_socket_t      *u;
    ngx_socket_t       s;

    u = lua_touserdata(L, 1);
    if (u == NULL) {
        return 0;
    }

    s = *u;
    if (s == -1) {
        return 0;
    }

    ngx_close_socket(s);
    *u = -1;

    return 0;
}



