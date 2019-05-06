
/*
 * Copyright (C) 
 * Modify by xxh
 */


#ifndef _NGX_TCP_H_INCLUDED_
#define _NGX_TCP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#if (NGX_TCP_SSL)
#include <ngx_tcp_ssl_module.h>
#endif



typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_tcp_conf_ctx_t;

/*保存解析listen后的配置信息*/
typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /*当前listen属于哪个server ctx */
    ngx_tcp_conf_ctx_t     *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
    unsigned                so_keepalive:2;
#if (NGX_TCP_SSL)
    unsigned                ssl:1;
#endif

    int                     backlog;
    int                     rcvbuf;
    int                     sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
/*NGX_HAVE_KEEPALIVE_TUNABLE 是configure时确定是否支持keepalive选项，见auto\unix 
    不受配置影响
*/
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t              deferred_accept;
#endif
} ngx_tcp_listen_t;


typedef struct {
    ngx_tcp_conf_ctx_t      *ctx;
    ngx_str_t                addr_text;
#if (NGX_TCP_SSL)
    ngx_uint_t               ssl;    /* unsigned   ssl:1; */
#endif
} ngx_tcp_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_tcp_addr_conf_t     conf;
} ngx_tcp_in_addr_t;


typedef struct {
    void                   *addrs; /* ngx_tcp_in_addr_t*/
    ngx_uint_t              naddrs;
} ngx_tcp_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_tcp_conf_addr_t */
} ngx_tcp_conf_port_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_tcp_conf_ctx_t     *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_TCP_SSL)
    unsigned                ssl:1;
#endif
    
    int                     backlog;
    int                     rcvbuf;
    int                     sndbuf;
    
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t              deferred_accept;
#endif
} ngx_tcp_conf_addr_t;


typedef struct {
    in_addr_t                mask;
    in_addr_t                addr;
    ngx_uint_t               deny;      /* unsigned  deny:1; */
} ngx_tcp_access_rule_t;


typedef struct {
    ngx_array_t             servers;     /* ngx_tcp_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_tcp_listen_t */
} ngx_tcp_core_main_conf_t;


typedef struct ngx_tcp_session_s  ngx_tcp_session_t;
typedef struct ngx_tcp_protocol_s  ngx_tcp_protocol_t;
typedef struct ngx_tcp_cleanup_s ngx_tcp_cleanup_t;
typedef void (*ngx_tcp_event_handler_pt)(ngx_tcp_session_t *s);
typedef ngx_int_t (*ngx_tcp_log_handler_pt)(ngx_tcp_session_t *s);
typedef void (*ngx_tcp_cleanup_pt)(void *data);

struct ngx_tcp_cleanup_s {
    ngx_tcp_cleanup_pt      handler;
    void                   *data;
    ngx_tcp_cleanup_t      *next;
};


typedef struct {
    ngx_tcp_protocol_t     *protocol;
    
    size_t                  connection_pool_size;
    size_t                  session_pool_size;
    size_t                  client_max_body_size;

    ngx_msec_t              read_timeout;
    ngx_msec_t              send_timeout;
    ngx_msec_t              keepalive_timeout;//allow NGX_CONF_UNSET_MSEC
    ngx_msec_t              resolver_timeout;

    ngx_flag_t              so_keepalive;

    /*ACL rules*/
    ngx_array_t             *rules;

    ngx_resolver_t          *resolver;

    /* server ctx */
    ngx_tcp_conf_ctx_t      *ctx;
    ngx_log_t               *error_log;

    ngx_tcp_log_handler_pt  log_handler;

    unsigned                listen:1;
} ngx_tcp_core_srv_conf_t;


struct ngx_tcp_session_s {
//    uint32_t             signature;         /* "TCP" */

    ngx_connection_t       *connection;
    ngx_pool_t             *pool;

    void                   *ctx;     /*TEMP only save current ctx*/
    void                  **main_conf;
    void                  **srv_conf;
    ngx_str_t              *addr_text;

    ngx_tcp_event_handler_pt         read_event_handler;
    ngx_tcp_event_handler_pt         write_event_handler;

    ngx_tcp_cleanup_t      *cleanup;
    
    time_t                  start_sec;
    ngx_msec_t              start_msec;

    ngx_tcp_log_handler_pt  log_handler;

#if (NGX_STAT_STUB)
    unsigned                stat_reading:1;
    unsigned                stat_writing:1;
    unsigned                padding:6;
#endif

};


typedef struct {
    ngx_str_t              *client;
    ngx_tcp_session_t      *session;
} ngx_tcp_log_ctx_t;



typedef void (*ngx_tcp_init_connection_pt)(ngx_event_t *rev);

#define NGX_TCP_PROTOCOL_SET   1
#define NGX_TCP_PROTOCOL_UNSET 0

struct ngx_tcp_protocol_s {
    ngx_str_t                   name;
    ngx_tcp_init_connection_pt  init_connection;
    ngx_flag_t                  set;
};


typedef struct {
    ngx_tcp_protocol_t         *protocol;
    ngx_int_t                  (*postconfiguration)(ngx_conf_t *cf);

    void                       *(*create_main_conf)(ngx_conf_t *cf);
    char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(ngx_conf_t *cf);
    char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                      void *conf);
} ngx_tcp_module_t;


#define NGX_TCP_MODULE         0x00504354     /* "TCP" */

#define NGX_TCP_MAIN_CONF      0x02000000
#define NGX_TCP_SRV_CONF       0x04000000
#define NGX_TCP_UPS_CONF       0x08000000


#define NGX_TCP_MAIN_CONF_OFFSET  offsetof(ngx_tcp_conf_ctx_t, main_conf)
#define NGX_TCP_SRV_CONF_OFFSET   offsetof(ngx_tcp_conf_ctx_t, srv_conf)

#define ngx_tcp_get_module_main_conf(s, module) (s)->main_conf[module.ctx_index]
#define ngx_tcp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_tcp_conf_get_module_main_conf(cf, module)                       \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_tcp_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define ngx_tcp_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_tcp_module.index] ?                                 \
        ((ngx_tcp_conf_ctx_t *) cycle->conf_ctx[ngx_tcp_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


void ngx_tcp_init_connection(ngx_connection_t *c);
void ngx_tcp_close_connection(ngx_connection_t *c);

u_char *ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len);
ngx_tcp_cleanup_t * ngx_tcp_cleanup_add(ngx_tcp_session_t *s, size_t size, ngx_pool_t *pool);

void ngx_tcp_block_reading(ngx_event_t *rev);
void ngx_tcp_empty_handler(ngx_event_t *wev);
void ngx_tcp_session_handler(ngx_event_t *ev);
void ngx_tcp_session_empty_handler(ngx_tcp_session_t *s);
void ngx_tcp_test_reading(ngx_tcp_session_t *s);
ngx_int_t ngx_tcp_access_handler(ngx_tcp_session_t *s);


extern ngx_module_t  ngx_tcp_module;
extern ngx_module_t  ngx_tcp_core_module;
extern ngx_uint_t    ngx_tcp_max_module;

#endif /* _NGX_TCP_H_INCLUDED_ */
