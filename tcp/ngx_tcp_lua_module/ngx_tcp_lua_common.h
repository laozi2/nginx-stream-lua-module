#ifndef NGX_TCP_LUA_COMMON_H
#define NGX_TCP_LUA_COMMON_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <math.h>
#include <assert.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "ngx_tcp.h"

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

/* Nginx TCP Lua Inline tag prefix */

#define NGX_TCP_LUA_INLINE_TAG "nhli_"

#define NGX_TCP_LUA_INLINE_TAG_LEN \
    (sizeof(NGX_TCP_LUA_INLINE_TAG) - 1)

#define NGX_TCP_LUA_INLINE_KEY_LEN \
    (NGX_TCP_LUA_INLINE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)

/* Nginx TCP Lua File tag prefix */

#define NGX_TCP_LUA_FILE_TAG "nhlf_"

#define NGX_TCP_LUA_FILE_TAG_LEN \
    (sizeof(NGX_TCP_LUA_FILE_TAG) - 1)

#define NGX_TCP_LUA_FILE_KEY_LEN \
    (NGX_TCP_LUA_FILE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)

typedef struct ngx_tcp_lua_main_conf_s ngx_tcp_lua_main_conf_t;

typedef ngx_int_t (*ngx_tcp_lua_conf_handler_pt)(ngx_log_t *log,
        ngx_tcp_lua_main_conf_t *lmcf, lua_State *L);


struct ngx_tcp_lua_main_conf_s {
    lua_State       *lua;

    ngx_str_t        lua_path;
    ngx_str_t        lua_cpath;

    ngx_pool_t      *pool;

    ngx_tcp_lua_conf_handler_pt     init_handler; /* for init_by_lua*/
    ngx_str_t                       init_src;

    ngx_array_t     *shm_zones;  /* of ngx_shm_zone_t* */
    ngx_uint_t       shm_zones_inited;

#if (NGX_PCRE)
    ngx_int_t        regex_cache_entries;
    ngx_int_t        regex_cache_max_entries;
    ngx_int_t        regex_match_limit;
#endif

    unsigned         requires_shm:1;
};


typedef struct ngx_tcp_lua_srv_conf_s {
    ngx_str_t                   lua_src;
    u_char                     *lua_src_key;
    
    ngx_flag_t                  enable_code_cache; /* whether to enable
                                                  code cache */
    
    size_t                      send_lowat;

    //ngx_msec_t                read_timeout;
    //ngx_msec_t                send_timeout;
    ngx_msec_t                  connect_timeout;
    
    ngx_uint_t                  pool_size;
    ngx_flag_t                  check_client_abort;

    unsigned                    lua_src_inline:1;
} ngx_tcp_lua_srv_conf_t;


typedef struct {
    uint8_t         type;

    union {
        int         b; /* boolean */
        lua_Number  n; /* number */
        ngx_str_t   s; /* string */
    } value;

} ngx_tcp_lua_value_t;

//typedef void (*ngx_tcp_cleanup_pt)(void *data);


typedef int (*ngx_tcp_lua_req_retval_handler)(ngx_tcp_session_t *s,lua_State *L);

typedef struct ngx_tcp_lua_ctx_s {

    void                    *data; /*save current upstream socket when handle event*/
    lua_State               *co;

    int                      cc_ref;            /*  reference to anchor coroutine in
                                               the lua registry */

    ngx_buf_t               *buf_in;
    ngx_buf_t               *buf_out;

    size_t                           length;
    size_t                           bytes_atleast;
    ngx_uint_t                       ft_type;
    ngx_err_t                        socket_errno;

    ngx_tcp_lua_req_retval_handler   prepare_retvals;

    ngx_event_t                      sleep;  /* used for ngx.sleep */

    unsigned         socket_invalid:1;
    unsigned         exited:1; /*marked the thread/session need exited*/
} ngx_tcp_lua_ctx_t;



//#define DDEBUG 1

#if defined(DDEBUG) && (DDEBUG)

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...) fprintf(stderr, "****** "); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

#   else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static void dd(const char* fmt, ...) {
}

#    endif

#else

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...)

#   else

#include <stdarg.h>

static void dd(const char* fmt, ...) {
}

#   endif

#endif


/*  coroutine anchoring table key in Lua vm registry */
//#define NGX_LUA_CORT_REF "ngx_lua_cort_ref"

/*  request ctx data anchoring table key in Lua vm registry */
//#define NGX_LUA_REQ_CTX_REF "ngx_lua_req_ctx_ref"


/*  globals symbol to hold nginx request pointer */
#define GLOBALS_SYMBOL_REQUEST    "ngx._req"

/*  globals symbol to hold code chunk handling nginx request */
#define GLOBALS_SYMBOL_RUNCODE    "ngx._code"


extern ngx_module_t ngx_tcp_lua_module;


#endif
