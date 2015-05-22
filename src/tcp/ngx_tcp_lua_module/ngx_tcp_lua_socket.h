#ifndef NGX_TCP_LUA_SOCKET_H
#define NGX_TCP_LUA_SOCKET_H

#include "ngx_tcp_lua_common.h"

typedef struct ngx_tcp_lua_socket_upstream_s  ngx_tcp_lua_socket_upstream_t;

typedef
    int (*ngx_tcp_lua_socket_tcp_retval_handler)(ngx_tcp_session_t *s,
        ngx_tcp_lua_socket_upstream_t *u, lua_State *L);

typedef void (*ngx_tcp_lua_socket_upstream_handler_pt)(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);

typedef struct {
    ngx_tcp_lua_main_conf_t          *conf;
    ngx_uint_t                         active_connections;

    /* queues of ngx_tcp_lua_socket_pool_item_t: */
    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    u_char                             key[1];

} ngx_tcp_lua_socket_pool_t;


typedef struct ngx_tcp_lua_dfa_edge_s ngx_tcp_lua_dfa_edge_t;


struct ngx_tcp_lua_dfa_edge_s {
    u_char                           chr;
    int                              new_state;
    ngx_tcp_lua_dfa_edge_t         *next;
};


typedef struct {
    ngx_tcp_lua_socket_upstream_t      *upstream;

    ngx_str_t                            pattern;
    int                                  state;
    ngx_tcp_lua_dfa_edge_t            **recovering;

    unsigned                             inclusive:1;
} ngx_tcp_lua_socket_compiled_pattern_t;


typedef struct {
    ngx_tcp_lua_socket_pool_t      *socket_pool;

    ngx_queue_t                      queue;
    ngx_connection_t                *connection;

    socklen_t                        socklen;
    struct sockaddr_storage          sockaddr;

    ngx_uint_t                       reused;

} ngx_tcp_lua_socket_pool_item_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    in_addr_t                       *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_tcp_upstream_resolved_t;


struct ngx_tcp_lua_socket_upstream_s {
    ngx_tcp_lua_socket_tcp_retval_handler      prepare_retvals;
    ngx_tcp_lua_socket_upstream_handler_pt     read_event_handler;
    ngx_tcp_lua_socket_upstream_handler_pt     write_event_handler;
    
    ngx_tcp_lua_socket_pool_t      *socket_pool;

    ngx_tcp_lua_srv_conf_t         *conf;
    ngx_tcp_cleanup_pt              cleanup; //*cleanup;
    ngx_tcp_session_t              *session;
    ngx_peer_connection_t           peer;

    ngx_msec_t                      read_timeout;
    ngx_msec_t                      send_timeout;
    ngx_msec_t                      connect_timeout;

    ngx_tcp_upstream_resolved_t    *resolved;

    ngx_buf_t                      *buf_in;
    ngx_buf_t                      *buf_out;

    size_t                          length;
    size_t                          rest;
    size_t                          bytes_atleast;
 
    ngx_uint_t                      ft_type;
    ngx_err_t                       socket_errno;
    
    ngx_int_t                     (*input_filter)(void *data, ssize_t bytes);
    void                           *input_filter_ctx;

    ngx_uint_t                      reused;

    unsigned                        waiting:1;
    unsigned                        eof:1;
};


//void ngx_tcp_lua_inject_req_socket_api(lua_State *L);
void ngx_tcp_lua_inject_socket_api(ngx_log_t *log, lua_State *L);

#endif
