
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>
//#include <ngx_tcp_variables.h>

typedef struct ngx_tcp_log_op_s  ngx_tcp_log_op_t;

typedef u_char *(*ngx_tcp_log_op_run_pt) (ngx_tcp_session_t *r, u_char *buf,
    ngx_tcp_log_op_t *op);

typedef size_t (*ngx_tcp_log_op_getlen_pt) (ngx_tcp_session_t *r,
    uintptr_t data);


struct ngx_tcp_log_op_s {
    size_t                      len;
    ngx_tcp_log_op_getlen_pt    getlen;
    ngx_tcp_log_op_run_pt       run;
    uintptr_t                   data;
};


typedef struct {
    ngx_str_t                   name;
    ngx_array_t                 *ops;        /* array of ngx_tcp_log_op_t */
} ngx_tcp_log_fmt_t;


typedef struct {
    ngx_array_t                 formats;    /* array of ngx_tcp_log_fmt_t */
    ngx_uint_t                  combined_used; /* unsigned  combined_used:1 */
} ngx_tcp_log_main_conf_t;


typedef struct {
    ngx_open_file_t             *file;
    time_t                      disk_full_time;
    time_t                      error_log_time;
    ngx_tcp_log_fmt_t           *format;
    ngx_socket_t                s_nlog;//NLOG
} ngx_tcp_log_t;


typedef struct {
    ngx_array_t                 *logs;       /* array of ngx_tcp_log_t */

    ngx_uint_t                  off;        /* unsigned  off:1 */
} ngx_tcp_log_srv_conf_t;


typedef struct {
    ngx_str_t                   name;
    size_t                      len;
    ngx_tcp_log_op_run_pt       run;
} ngx_tcp_log_var_t;


static void ngx_tcp_log_write(ngx_tcp_session_t *r, ngx_tcp_log_t *log,
    u_char *buf, size_t len);

static u_char *ngx_tcp_log_remote_addr(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);

static u_char *ngx_tcp_log_time(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);

static u_char *ngx_tcp_log_iso8601(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);

static u_char *ngx_tcp_log_msec(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);

static u_char *ngx_tcp_log_request_time(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);

static u_char *ngx_tcp_log_connection(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);

static u_char *ngx_tcp_log_connection_requests(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);
// static u_char *ngx_tcp_log_bytes_sent(ngx_tcp_session_t *s, u_char *buf,
//     ngx_tcp_log_op_t *op);

// static u_char *ngx_tcp_log_request_length(ngx_tcp_session_t *s, u_char *buf,
//     ngx_tcp_log_op_t *op);
static u_char *ngx_tcp_log_bytes_sent(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);

static u_char *ngx_tcp_log_protocol(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op);
// static ngx_int_t ngx_tcp_log_variable_compile(ngx_conf_t *cf,
//     ngx_tcp_log_op_t *op, ngx_str_t *value);
// static size_t ngx_tcp_log_variable_getlen(ngx_tcp_session_t *r,
//     uintptr_t data);
// static u_char *ngx_tcp_log_variable(ngx_tcp_session_t *s, u_char *buf,
//     ngx_tcp_log_op_t *op);
// static uintptr_t ngx_tcp_log_escape(u_char *dst, u_char *src, size_t size);

static void *ngx_tcp_log_create_main_conf(ngx_conf_t *cf);

static void *ngx_tcp_log_create_srv_conf(ngx_conf_t *cf);

static char *ngx_tcp_log_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_tcp_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_tcp_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_tcp_log_compile_format(ngx_conf_t *cf, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);

static ngx_int_t ngx_tcp_log_init(ngx_conf_t *cf);
static ngx_int_t ngx_tcp_log_handler(ngx_tcp_session_t *s);

static char *ngx_access_nlog(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);//NLOG
static void ngx_clean_nlog_sock(void* data);//NLOG


static ngx_command_t  ngx_tcp_log_commands[] = {

    { ngx_string("log_format"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_2MORE,
      ngx_tcp_log_set_format,
      NGX_TCP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("access_log"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_tcp_log_set_log,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

/*------------------------NLOG------------------------*/
    { ngx_string("access_nlog"),
     NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE2,
     ngx_access_nlog,
     NGX_TCP_SRV_CONF_OFFSET,
     0,
     NULL},
/*------------------------NLOG------------------------*/
      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_log_module_ctx = {
    NULL,                                  /* protocol */
    ngx_tcp_log_init,                      /* postconfiguration */
    ngx_tcp_log_create_main_conf,          /* create main configuration */
    NULL,                                  /* init main configuration */
    ngx_tcp_log_create_srv_conf,           /* create server configuration */
    ngx_tcp_log_merge_srv_conf,            /* merge server configuration */

    NULL                                   /* valid server configuration */
};


ngx_module_t  ngx_tcp_log_module = {
    NGX_MODULE_V1,
    &ngx_tcp_log_module_ctx,              /* module context */
    ngx_tcp_log_commands,                 /* module directives */
    NGX_TCP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_str_t  ngx_tcp_access_log = ngx_string("logs/access_tcp.log"); //like NGX_HTTP_LOG_PATH

static ngx_str_t  ngx_tcp_combined_fmt =
    ngx_string("$remote_addr $time_iso8601 $msec $request_time $connection $connection_requests $protocol");

static ngx_tcp_log_var_t  ngx_tcp_log_vars[] = {
    { ngx_string("remote_addr"), sizeof("255.255.255.255") - 1,
                          ngx_tcp_log_remote_addr },

    { ngx_string("time_local"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
                          ngx_tcp_log_time },

    { ngx_string("time_iso8601"), sizeof("1970-09-28T12:00:00+06:00") - 1,
                          ngx_tcp_log_iso8601 },

    { ngx_string("msec"), NGX_TIME_T_LEN + 4, ngx_tcp_log_msec },           /*NGX_TIME_T_LEN + 4,*/

    { ngx_string("request_time"), sizeof("\033[0;32;40m0.000\033[0m")-1,
                          ngx_tcp_log_request_time },

    { ngx_string("connection"), NGX_ATOMIC_T_LEN,
                          ngx_tcp_log_connection },

    { ngx_string("connection_requests"), NGX_INT_T_LEN,
                          ngx_tcp_log_connection_requests},

    { ngx_string("bytes_sent"), NGX_OFF_T_LEN,
                          ngx_tcp_log_bytes_sent},

    { ngx_string("protocol"), 20,
                          ngx_tcp_log_protocol },

    { ngx_null_string, 0, NULL }
};


static ngx_int_t
ngx_tcp_log_handler(ngx_tcp_session_t *s)
{
    u_char                   *line, *p;
    size_t                   len;
    ngx_uint_t               i, l;
    ngx_tcp_log_t            *log;
    ngx_tcp_log_op_t         *op;
    // ngx_tcp_log_buf_t       *buffer;
    ngx_tcp_log_srv_conf_t  *lscf;
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp log handler");

    lscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_log_module);

    if (lscf->off) {
        return NGX_OK;
    }

    log = lscf->logs->elts;
    for (l = 0; l < lscf->logs->nelts; l++) {

        if (ngx_time() == log[l].disk_full_time) {
            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */
            continue;
        }

        len = 0;
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(s, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        len += NGX_LINEFEED_SIZE;
        // buffer = log[l].file ? log[l].file->data : NULL;
        // if (buffer) {

            // if (len > (size_t) (buffer->last - buffer->pos)) {

                // ngx_tcp_log_write(s, &log[l], buffer->start,
                //                    buffer->pos - buffer->start);

                // buffer->pos = buffer->start;
            // }

            // if (len <= (size_t) (buffer->last - buffer->pos)) {

            //     p = buffer->pos;

            //     if (buffer->event && p == buffer->start) {
            //         ngx_add_timer(buffer->event, buffer->flush);
            //     }

            //     for (i = 0; i < log[l].format->ops->nelts; i++) {
            //         p = op[i].run(s, p, &op[i]);
            //     }

            //     ngx_linefeed(p);

            //     buffer->pos = p;

            //     continue;
            // }

            // if (buffer->event && buffer->event->timer_set) {
            //     ngx_del_timer(buffer->event);
            // }
        // }

        line = ngx_pnalloc(s->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        p = line;

        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(s, p, &op[i]);
        }

        ngx_linefeed(p);
        ngx_tcp_log_write(s, &log[l], line, p - line);
    }
    return NGX_OK;
}


static void
ngx_tcp_log_write(ngx_tcp_session_t *s, ngx_tcp_log_t *log, u_char *buf,
    size_t len)
{
    u_char              *name;
    // time_t               now;
    ssize_t              n;
    // ngx_err_t            err;
    // if (log->script == NULL) {
    name = log->file->name.data;
/*------------------------NLOG------------------------*/
    if (log->s_nlog == -1) {
        n = ngx_write_fd(log->file->fd, buf, len);
    }
    else {
        n = send(log->s_nlog, buf, len, 0);
    }
/*------------------------NLOG------------------------*/

    // } else {
    //     name = NULL;
    //     n = ngx_tcp_log_script_write(s, log->script, &name, buf, len);
    // }

    // if (n == (ssize_t) len) {
    //     return;
    // }

    // now = ngx_time();

    // if (n == -1) {
    //     err = ngx_errno;

    //     if (err == NGX_ENOSPC) {
    //         log->disk_full_time = now;
    //     }

    //     if (now - log->error_log_time > 59) {
    //         ngx_log_error(NGX_LOG_ALERT, s->connection->log, err,
    //                       ngx_write_fd_n " to \"%s\" failed", name);

    //         log->error_log_time = now;
    //     }

    //     return;
    // }

    // if (now - log->error_log_time > 59) {
    //     ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
    //                   ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
    //                   name, n, len);

    //     log->error_log_time = now;
    // }
}

static u_char *
ngx_tcp_log_copy_short(ngx_tcp_session_t *r, u_char *buf ,
    ngx_tcp_log_op_t *op)
{
    size_t     len;
    uintptr_t  data;

    len = op->len;
    data = op->data;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


static u_char *
ngx_tcp_log_copy_long(ngx_tcp_session_t *r, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    return ngx_cpymem(buf, (u_char *) op->data, op->len);
}

static u_char *ngx_tcp_log_remote_addr(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    //ngx_tcp_log_srv_conf_t   *lmcf;
    ngx_connection_t       *c;
    c = s->connection;
    return ngx_cpymem(buf,c->addr_text.data ,c->addr_text.len);
}

static u_char *
ngx_tcp_log_time(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    return ngx_cpymem(buf, ngx_cached_http_log_time.data,
                      ngx_cached_http_log_time.len);
}

static u_char *
ngx_tcp_log_iso8601(ngx_tcp_session_t *s, u_char *buf ,
    ngx_tcp_log_op_t *op)
{
    return ngx_cpymem(buf, ngx_cached_http_log_iso8601.data,
                      ngx_cached_http_log_iso8601.len);
}

static u_char *
ngx_tcp_log_msec(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_time_t  *tp;
    tp = ngx_timeofday();
    return ngx_sprintf(buf, "%T.%03M", tp->sec, tp->msec);
}

static u_char *
ngx_tcp_log_request_time(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_time_t      *tp;
    ngx_msec_int_t   ms;

    ngx_time_update();//tmp
    tp = ngx_timeofday();

    ms = (ngx_msec_int_t)
             ((tp->sec - s->start_sec) * 1000 + (tp->msec - s->start_msec));
    ms = ngx_max(ms, 0);
/************************colorful request time**********************************************/

    if (ms < 10) {
        return ngx_sprintf(buf, "%T.%03M", ms / 1000, ms % 1000);
    }
    else if (ms < 100) {
        return ngx_sprintf(buf,"\033[0;36;40m%T.%03M\033[0m", ms / 1000, ms % 1000);
    }
    else if (ms < 500) {
        return ngx_sprintf(buf,"\033[0;33;40m%T.%03M\033[0m", ms / 1000, ms % 1000);
    }
    else {
        return ngx_sprintf(buf,"\033[0;31;40m%T.%03M\033[0m", ms / 1000, ms % 1000);
    }

/************************colorful request time**********************************************/

    return ngx_sprintf(buf, "%T.%03M", ms / 1000, ms % 1000);
}

static u_char *
ngx_tcp_log_connection(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    return ngx_sprintf(buf , "%uA", s->connection->number);
}

static u_char *
ngx_tcp_log_connection_requests(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    return ngx_sprintf(buf, "%uA", s->connection->requests);
}

// static u_char *
// ngx_tcp_log_bytes_sent(ngx_tcp_session_t *s, u_char *buf,
//     ngx_tcp_log_op_t *op)
// {
//     return ngx_sprintf(buf, "%O", s->connection->sent);
// }


// /*
//  * this log operation code function is more optimized for logging
//  */

// static u_char *
// ngx_tcp_log_body_bytes_sent(ngx_tcp_session_t *s, u_char *buf,
//     ngx_tcp_log_op_t *op)
// {
//     off_t  length;

//     length = s->connection->sent - s->header_size;

//     if (length > 0) {
//         return ngx_sprintf(buf, "%O", length);
//     }

//     *buf = '0';

//     return buf + 1;
// }


// static u_char *
// ngx_tcp_log_request_length(ngx_tcp_session_t *s, u_char *buf,
//     ngx_tcp_log_op_t *op)
// {
//     // return ngx_sprintf(buf, "%O", s->request_length);
//     //通过session还不能获取请求的长度，暂时返回0
//     return ngx_sprintf(buf, "%O", 0);
// }

static u_char *ngx_tcp_log_bytes_sent(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    return ngx_sprintf(buf, "%O", s->connection->sent);
}

static u_char *ngx_tcp_log_protocol(ngx_tcp_session_t *s, u_char *buf,
    ngx_tcp_log_op_t *op)
{
    ngx_tcp_core_srv_conf_t   *cscf;
    cscf= ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
    return ngx_sprintf(buf,"%V",&cscf->protocol->name);
}

// static ngx_int_t
// ngx_tcp_log_variable_compile(ngx_conf_t *cf, ngx_tcp_log_op_t *op,
//     ngx_str_t *value)
// {
//     ngx_int_t  index;

//     index = ngx_tcp_get_variable_index(cf, value);
//     if (index == NGX_ERROR) {
//         return NGX_ERROR;
//     }

//     op->len = 0;
//     op->getlen = ngx_tcp_log_variable_getlen;
//     op->run = ngx_tcp_log_variable;
//     op->data = index;

//     return NGX_OK;
// }

// static size_t
// ngx_tcp_log_variable_getlen(ngx_tcp_session_t *r, uintptr_t data)
// {
//     uintptr_t                   len;
//     ngx_tcp_variable_value_t  *value;

//     value = ngx_tcp_get_indexed_variable(r, data);

//     if (value == NULL || value->not_found) {
//         return 1;
//     }

//     len = ngx_tcp_log_escape(NULL, value->data, value->len);

//     value->escape = len ? 1 : 0;

//     return value->len + len * 3;
// }


// static u_char *
// ngx_tcp_log_variable(ngx_tcp_session_t *s, u_char *buf, ngx_tcp_log_op_t *op)
// {
//     ngx_tcp_variable_value_t  *value;

//     value = ngx_tcp_get_indexed_variable(s, op->data);

//     if (value == NULL || value->not_found) {
//         *buf = '-';
//         return buf + 1;
//     }

//     if (value->escape == 0) {
//         return ngx_cpymem(buf, value->data, value->len);

//     } else {
//         return (u_char *) ngx_tcp_log_escape(buf, value->data, value->len);
//     }
// }


// static uintptr_t
// ngx_tcp_log_escape(u_char *dst, u_char *src, size_t size)
// {
//     ngx_uint_t      n;
//     static u_char   hex[] = "0123456789ABCDEF";

//     static uint32_t   escape[] = {
//         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

//                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
//         0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

//                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
//         0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

//                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
//         0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

//         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
//         0xffffffff,  1111 1111 1111 1111  1111 1111 1111 1111
//         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
//         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
//     };


//     if (dst == NULL) {

//         /* find the number of the characters to be escaped */

//         n = 0;

//         while (size) {
//             if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
//                 n++;
//             }
//             src++;
//             size--;
//         }

//         return (uintptr_t) n;
//     }

//     while (size) {
//         if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
//             *dst++ = '\\';
//             *dst++ = 'x';
//             *dst++ = hex[*src >> 4];
//             *dst++ = hex[*src & 0xf];
//             src++;

//         } else {
//             *dst++ = *src++;
//         }
//         size--;
//     }

//     return (uintptr_t) dst;
// }

static void *
ngx_tcp_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_log_main_conf_t  *conf;

    ngx_tcp_log_fmt_t  *fmt;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_log_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->formats, cf->pool, 4, sizeof(ngx_tcp_log_fmt_t))
        != NGX_OK)
    {
        return NULL;
    }

    fmt = ngx_array_push(&conf->formats);
    if (fmt == NULL) {
        return NULL;
    }

    ngx_str_set(&fmt->name, "combined");


    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_tcp_log_op_t));
    if (fmt->ops == NULL) {
        return NULL;
    }

    return conf;
}


static void *
ngx_tcp_log_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_log_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_log_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}

static char *
ngx_tcp_log_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_tcp_log_srv_conf_t *prev = parent;
    ngx_tcp_log_srv_conf_t *conf = child;

    ngx_tcp_log_t            *log;
    ngx_tcp_log_fmt_t        *fmt;
    ngx_tcp_log_main_conf_t  *lmcf;
    ngx_tcp_core_srv_conf_t  *cscf;

    cscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_core_module);
    cscf->log_handler = ngx_tcp_log_handler;

    if (conf->logs || conf->off) {
        return NGX_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    if (conf->logs || conf->off) {
        return NGX_CONF_OK;
    }

    conf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_tcp_log_t));
    if (conf->logs == NULL) {
        return NGX_CONF_ERROR;
    }

    log = ngx_array_push(conf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    log->file = ngx_conf_open_file(cf->cycle, &ngx_tcp_access_log);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    // log->script = NULL;
    log->disk_full_time = 0;
    log->error_log_time = 0;

    lmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_log_module);
    fmt = lmcf->formats.elts;

    // the default "combined" format
    log->format = &fmt[0];
    lmcf->combined_used = 1;

    return NGX_CONF_OK;
}

static char *
ngx_tcp_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_log_srv_conf_t *lscf = conf;

    // ssize_t                     size;
    ngx_uint_t                  i;
    // ngx_msec_t                  flush;
    ngx_str_t                  *value, name;
    ngx_tcp_log_t              *log;
    // ngx_tcp_log_buf_t         *buffer;
    ngx_tcp_log_fmt_t          *fmt;
    ngx_tcp_log_main_conf_t    *lmcf;
    // ngx_tcp_script_compile_t   sc;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lscf->off = 1;
        if (cf->args->nelts == 2) {
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }


    if (lscf->logs == NULL) {
        lscf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_tcp_log_t));
        if (lscf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    lmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_log_module);

    log = ngx_array_push(lscf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_tcp_log_t));

    log->s_nlog = -1; //NLOG

    log->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }


    if (cf->args->nelts > 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "too many parameter , not more than 3 parameter");
        return NGX_CONF_ERROR;
    }
    else if (cf->args->nelts == 3) {
        name = value[2];

        if (ngx_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }

    } else {
        ngx_str_set(&name, "combined");
        lmcf->combined_used = 1;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            break;
        }
    }

    if (log->format == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown log format \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_tcp_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_log_main_conf_t *lmcf = conf;

    ngx_str_t           *value;
    ngx_uint_t           i;
    ngx_tcp_log_fmt_t  *fmt;

    if (cf->cmd_type != NGX_TCP_MAIN_CONF) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "the \"log_format\" directive may be used "
                           "only on \"tcp\" level");
    }

    value = cf->args->elts;

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len
            && ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"log_format\" name \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];


    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_tcp_log_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    return ngx_tcp_log_compile_format(cf,  fmt->ops, cf->args, 2);
}


static char *
ngx_tcp_log_compile_format(ngx_conf_t *cf,
    ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s)
{
    u_char              *data,*p, ch;
    size_t               i, len;
    ngx_str_t           *value, var;
    ngx_uint_t           bracket;
    ngx_tcp_log_op_t   *op;
    ngx_tcp_log_var_t  *v;

    value = args->elts;

    for ( /* void */ ; s < args->nelts; s++) {

        i = 0;

        while (i < value[s].len) {

            op = ngx_array_push(ops);
            if (op == NULL) {
                return NGX_CONF_ERROR;
            }

            data = &value[s].data[i];

            if (value[s].data[i] == '$') {

                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = &value[s].data[i];

                } else {
                    bracket = 0;
                    var.data = &value[s].data[i];
                }

                for (var.len = 0; i < value[s].len; i++, var.len++) {
                    ch = value[s].data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return NGX_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                for (v = ngx_tcp_log_vars; v->name.len; v++) {

                    if (v->name.len == var.len
                        && ngx_strncmp(v->name.data, var.data, var.len) == 0)
                    {
                        op->len = v->len;
                        op->getlen = NULL;
                        op->run = v->run;
                        op->data = 0;

                        goto found;
                    }
                }
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable \"%V\"", &var);
                return NGX_CONF_ERROR;
                // if (ngx_tcp_log_variable_compile(cf, op, &var) != NGX_OK) {
                //     return NGX_CONF_ERROR;
                // }

            found:

                continue;
            }

            i++;

            while (i < value[s].len && value[s].data[i] != '$') {
                i++;
            }

            len = &value[s].data[i] - data;

            if (len) {

                op->len = len;
                op->getlen = NULL;

                if (len <= sizeof(uintptr_t)) {
                    op->run = ngx_tcp_log_copy_short;
                    op->data = 0;

                    while (len--) {
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {
                    op->run = ngx_tcp_log_copy_long;

                    p = ngx_pnalloc(cf->pool, len);
                    if (p == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    ngx_memcpy(p, data, len);
                    op->data = (uintptr_t) p;
                }
            }
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_tcp_log_init(ngx_conf_t *cf)
{
    ngx_str_t                  *value;
    ngx_array_t                 a;
    //ngx_tcp_handler_pt        *h;
    ngx_tcp_log_fmt_t         *fmt;
    ngx_tcp_log_main_conf_t   *lmcf;
    //ngx_tcp_core_srv_conf_t   *cscf;

    lmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_log_module);

    if (lmcf->combined_used) {
        if (ngx_array_init(&a, cf->pool, 1, sizeof(ngx_str_t)) != NGX_OK) {
            return NGX_ERROR;
        }

        value = ngx_array_push(&a);
        if (value == NULL) {
            return NGX_ERROR;
        }

        *value = ngx_tcp_combined_fmt;
        fmt = lmcf->formats.elts;

        if (ngx_tcp_log_compile_format(cf, fmt->ops, &a, 0)
            != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*------------------------NLOG------------------------*/
//char *ngx_access_nlog(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
//{
//    ngx_tcp_log_srv_conf_t *lscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_log_module);
//    ngx_tcp_log_t             *log = NULL;
//    int sock = -1;
//    ngx_str_t  *value, localaddr, remoteaddress;
//    char* pos;
//    char rip[16];
//    int val = 1;
//    unsigned short lport,rport;
//
//    if (cf->args->nelts != 3) {
//        return "nlog arguments wrong";
//    }
//
//    if (NULL == lscf->logs) {
//            return NGX_CONF_ERROR;
//    }
//
//    log = (ngx_tcp_log_t*)(lscf->logs->elts);
//
//    if (NULL == log) {
//            return NGX_CONF_ERROR;
//    }
//
//    if(-1 != log->sock){
//         return NGX_CONF_ERROR;
//    }
//
//
//    value = cf->args->elts;
//
//    localaddr = value[1];
//    remoteaddress= value[2];
//
//    // access_nlog 127.0.0.1:5050  192.168.0.25:5151
//    pos = strchr((char*)localaddr.data,':');
//    if(NULL == pos){
//        return NGX_CONF_ERROR;
//    }
//    lport = (unsigned short)atoi(pos+1);
//    pos = strchr((char*)remoteaddress.data,':');
//    if(NULL == pos){
//        return NGX_CONF_ERROR;
//    }
//    rport = (unsigned short)atoi(pos+1);
//    int len = pos - (char*)remoteaddress.data;
//    if(len <= 0 || len >= 16){
//        return NGX_CONF_ERROR;
//    }
//    memcpy(rip,remoteaddress.data,len);
//    rip[len] = '\0';
//
//    struct sockaddr_in laddr;
//    laddr.sin_family = AF_INET;
//    laddr.sin_port =  htons(lport);
//    laddr.sin_addr.s_addr = INADDR_ANY;
//
//    struct sockaddr_in remoteaddr;
//    memset(&remoteaddr,0,sizeof(remoteaddr));
//    remoteaddr.sin_family = AF_INET;
//    remoteaddr.sin_port =  htons(rport);
//    remoteaddr.sin_addr.s_addr = inet_addr (rip);
//
//    if ((sock = socket (PF_INET, SOCK_DGRAM, 0)) < 0){
//        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
//                               "access_nlog socket create  err ");
//        return NGX_CONF_ERROR;
//    }
//
//    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &val, sizeof (val)) != 0){
//        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
//                               "access_nlog socket reuse bind err ");
//          return NGX_CONF_ERROR;
//    }
//
//    if (bind (sock, (struct sockaddr *) &laddr, sizeof (laddr)) < 0){
//        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
//                               "access_nlog socket bind err ");
//        return NGX_CONF_ERROR;
//    }
//
//    log->sock =  sock;
//    log->raddr = remoteaddr;
//    ngx_pool_cleanup_t* pct = ngx_pool_cleanup_add(cf->pool, sizeof(int));
//    pct->data = (void*)&(log->sock);
//    pct->handler = ngx_cleansock;
//
//    return NGX_CONF_OK;
//}
//

char *ngx_access_nlog(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_log_srv_conf_t     *llcf;
    ngx_tcp_log_t              *log;
    ngx_str_t                  *value;
    ngx_url_t                   u_l;
    ngx_url_t                   u_r;
    ngx_socket_t                s;
    int                         reuseaddr;
    ngx_pool_cleanup_t         *cln;

    llcf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_log_module);
    
    if (llcf->off == 1) {
        return NGX_CONF_OK;
    }

    if (NULL == llcf->logs) {
        return "need set access_log first";
    }
    
    log = (ngx_tcp_log_t*)(llcf->logs->elts);
    
    if (NULL == log) {
        return "need set access_log first";
    }

    if (log->s_nlog != -1) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u_l, sizeof(ngx_url_t));
    u_l.url = value[1];
    u_l.default_port = (in_port_t) 0;
    u_l.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u_l) != NGX_OK) {
        if (u_l.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"nlog\" directive",
                               u_l.err, &u_l.url);
        }

        return NGX_CONF_ERROR;
    }

    if (u_l.no_port || u_l.family != AF_INET) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                                "no valid port or no valid ipv4 address");

        return NGX_CONF_ERROR;
    }
    
    ngx_memzero(&u_r, sizeof(ngx_url_t));
    u_r.url = value[2];
    u_r.default_port = (in_port_t) 0;
    u_r.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u_r) != NGX_OK) {
        if (u_r.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"nlog\" directive",
                               u_r.err, &u_r.url);
        }

        return NGX_CONF_ERROR;
    }
    
    if (u_r.no_port || u_r.family != AF_INET) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                                "no valid port or no valid ipv4 address");

        return NGX_CONF_ERROR;
    }

    s = ngx_socket(AF_INET, SOCK_DGRAM, 0);

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"nlog create udp socket %d",s);

    if (s == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "socket() failed, %d", ngx_socket_errno);

        return NGX_CONF_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_nonblocking() failed, %d", ngx_socket_errno);
        
        goto failed;
    }

    reuseaddr = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int))
                == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "setsockopt() failed, %d", ngx_socket_errno);
        
        goto failed;
    }

    if (bind(s, (struct sockaddr_in*) &u_l.sockaddr, u_l.socklen) == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bind() failed, %d", ngx_socket_errno);

        goto failed;
    }
    
    if (connect(s, (struct sockaddr_in*) &u_r.sockaddr, u_r.socklen) == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "connect() failed, %d", ngx_socket_errno);

        goto failed;
    }
    
    log->s_nlog = s;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    cln->data = log;
    cln->handler = ngx_clean_nlog_sock;
    
    return NGX_CONF_OK;

failed:

    if (ngx_close_socket(s) == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_close_socket() failed, %d", ngx_socket_errno);
    }

    return NGX_CONF_ERROR;
}

static void ngx_clean_nlog_sock(void* data)
{
    ngx_tcp_log_t  *log;

    log = data;
    if (log->s_nlog != -1) {
        ngx_close_socket(log->s_nlog);
        log->s_nlog = -1;
    }
}
/*------------------------NLOG------------------------*/
