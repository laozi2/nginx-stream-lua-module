
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

static char *ngx_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_nlog(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);//NLOG
static void ngx_clean_nlog_sock(void* data);//NLOG

static ngx_command_t  ngx_errlog_commands[] = {

    {ngx_string("error_log"),
     NGX_MAIN_CONF|NGX_CONF_1MORE,
     ngx_error_log,
     0,
     0,
     NULL},
/*------------------------NLOG------------------------*/
    {ngx_string("nlog"),
     NGX_MAIN_CONF|NGX_CONF_TAKE2,
     ngx_nlog,
     0,
     0,
     NULL},
/*------------------------NLOG------------------------*/     
    ngx_null_command
};


static ngx_core_module_t  ngx_errlog_module_ctx = {
    ngx_string("errlog"),
    NULL,
    NULL
};


ngx_module_t  ngx_errlog_module = {
    NGX_MODULE_V1,
    &ngx_errlog_module_ctx,                /* module context */
    ngx_errlog_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_log_t        ngx_log;
static ngx_open_file_t  ngx_log_file;
ngx_uint_t              ngx_use_stderr = 1;


static ngx_str_t err_levels[] = {
    ngx_null_string,
    ngx_string("emerg"),
    ngx_string("alert"),
    ngx_string("crit"),
    ngx_string("error"),
    ngx_string("warn"),
    ngx_string("notice"),
    ngx_string("info"),
    ngx_string("debug")
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_mysql","debug_tcp"
};


#if (NGX_HAVE_VARIADIC_MACROS)

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)

#else

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, va_list args)

#endif
{
#if (NGX_HAVE_VARIADIC_MACROS)
    va_list  args;
#endif
    u_char  *p, *last, *msg;
    u_char   errstr[NGX_MAX_ERROR_STR];

    if (log->file->fd == NGX_INVALID_FILE) {
        return;
    }

    last = errstr + NGX_MAX_ERROR_STR;

    ngx_memcpy(errstr, ngx_cached_err_log_time.data,
               ngx_cached_err_log_time.len);

    p = errstr + ngx_cached_err_log_time.len;

    p = ngx_slprintf(p, last, " [%V] ", &err_levels[level]);

    /* pid#tid */
    p = ngx_slprintf(p, last, "%P#" NGX_TID_T_FMT ": ",
                    ngx_log_pid, ngx_log_tid);

    if (log->connection) {
        p = ngx_slprintf(p, last, "*%uA ", log->connection);
    }

    msg = p;

#if (NGX_HAVE_VARIADIC_MACROS)

    va_start(args, fmt);
    p = ngx_vslprintf(p, last, fmt, args);
    va_end(args);

#else

    p = ngx_vslprintf(p, last, fmt, args);

#endif

    if (err) {
        p = ngx_log_errno(p, last, err);
    }

    if (level != NGX_LOG_DEBUG && log->handler) {
        p = log->handler(log, p, last - p);
    }

    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    ngx_linefeed(p);
/*------------------------NLOG------------------------*/
    if (log->fd == -1) {
/*------------------------NLOG------------------------*/    
        (void) ngx_write_fd(log->file->fd, errstr, p - errstr);
/*------------------------NLOG------------------------*/
    }
    else {
        (void) send(log->fd, errstr, p - errstr, 0);
    }
/*------------------------NLOG------------------------*/    

    if (!ngx_use_stderr
        || level > NGX_LOG_WARN
        || log->file->fd == ngx_stderr)
    {
        return;
    }

    msg -= (7 + err_levels[level].len + 3);

    (void) ngx_sprintf(msg, "nginx: [%V] ", &err_levels[level]);

    (void) ngx_write_console(ngx_stderr, msg, p - msg);
}


#if !(NGX_HAVE_VARIADIC_MACROS)

void ngx_cdecl
ngx_log_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    va_list  args;

    if (log->log_level >= level) {
        va_start(args, fmt);
        ngx_log_error_core(level, log, err, fmt, args);
        va_end(args);
    }
}


void ngx_cdecl
ngx_log_debug_core(ngx_log_t *log, ngx_err_t err, const char *fmt, ...)
{
    va_list  args;

    va_start(args, fmt);
    ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, args);
    va_end(args);
}

#endif


void ngx_cdecl
ngx_log_abort(ngx_err_t err, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;
    u_char    errstr[NGX_MAX_CONF_ERRSTR];

    va_start(args, fmt);
    p = ngx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                  "%*s", p - errstr, errstr);
}


void ngx_cdecl
ngx_log_stderr(ngx_err_t err, const char *fmt, ...)
{
    u_char   *p, *last;
    va_list   args;
    u_char    errstr[NGX_MAX_ERROR_STR];

    last = errstr + NGX_MAX_ERROR_STR;
    p = errstr + 7;

    ngx_memcpy(errstr, "nginx: ", 7);

    va_start(args, fmt);
    p = ngx_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = ngx_log_errno(p, last, err);
    }

    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    ngx_linefeed(p);

    (void) ngx_write_console(ngx_stderr, errstr, p - errstr);
}


u_char *
ngx_log_errno(u_char *buf, u_char *last, ngx_err_t err)
{
    if (buf > last - 50) {

        /* leave a space for an error code */

        buf = last - 50;
        *buf++ = '.';
        *buf++ = '.';
        *buf++ = '.';
    }

#if (NGX_WIN32)
    buf = ngx_slprintf(buf, last, ((unsigned) err < 0x80000000)
                                       ? " (%d: " : " (%Xd: ", err);
#else
    buf = ngx_slprintf(buf, last, " (%d: ", err);
#endif

    buf = ngx_strerror(err, buf, last - buf);

    if (buf < last) {
        *buf++ = ')';
    }

    return buf;
}


ngx_log_t *
ngx_log_init(u_char *prefix)
{
    u_char  *p, *name;
    size_t   nlen, plen;

    ngx_log.file = &ngx_log_file;
    ngx_log.log_level = NGX_LOG_NOTICE;

    name = (u_char *) NGX_ERROR_LOG_PATH;

    /*
     * we use ngx_strlen() here since BCC warns about
     * condition is always false and unreachable code
     */

    nlen = ngx_strlen(name);

    if (nlen == 0) {
        ngx_log_file.fd = ngx_stderr;
        return &ngx_log;
    }

    p = NULL;

#if (NGX_WIN32)
    if (name[1] != ':') {
#else
    if (name[0] != '/') {
#endif

        if (prefix) {
            plen = ngx_strlen(prefix);

        } else {
#ifdef NGX_PREFIX
            prefix = (u_char *) NGX_PREFIX;
            plen = ngx_strlen(prefix);
#else
            plen = 0;
#endif
        }

        if (plen) {
            name = malloc(plen + nlen + 2);
            if (name == NULL) {
                return NULL;
            }

            p = ngx_cpymem(name, prefix, plen);

            if (!ngx_path_separator(*(p - 1))) {
                *p++ = '/';
            }

            ngx_cpystrn(p, (u_char *) NGX_ERROR_LOG_PATH, nlen + 1);

            p = name;
        }
    }

    ngx_log_file.fd = ngx_open_file(name, NGX_FILE_APPEND,
                                    NGX_FILE_CREATE_OR_OPEN,
                                    NGX_FILE_DEFAULT_ACCESS);

    if (ngx_log_file.fd == NGX_INVALID_FILE) {
        ngx_log_stderr(ngx_errno,
                       "[alert] could not open error log file: "
                       ngx_open_file_n " \"%s\" failed", name);
#if (NGX_WIN32)
        ngx_event_log(ngx_errno,
                       "could not open error log file: "
                       ngx_open_file_n " \"%s\" failed", name);
#endif

        ngx_log_file.fd = ngx_stderr;
    }

    if (p) {
        ngx_free(p);
    }

    return &ngx_log;
}


ngx_log_t *
ngx_log_create(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_log_t  *log;

    log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        return NULL;
    }

    log->file = ngx_conf_open_file(cycle, name);
    if (log->file == NULL) {
        return NULL;
    }

    return log;
}


char *
ngx_log_set_levels(ngx_conf_t *cf, ngx_log_t *log)
{
    ngx_uint_t   i, n, d, found;
    ngx_str_t   *value;

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {
        found = 0;

        for (n = 1; n <= NGX_LOG_DEBUG; n++) {
            if (ngx_strcmp(value[i].data, err_levels[n].data) == 0) {

                if (log->log_level != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level = n;
                found = 1;
                break;
            }
        }

        for (n = 0, d = NGX_LOG_DEBUG_FIRST; d <= NGX_LOG_DEBUG_LAST; d <<= 1) {
            if (ngx_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~NGX_LOG_DEBUG_ALL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level |= d;
                found = 1;
                break;
            }
        }


        if (!found) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid log level \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (log->log_level == NGX_LOG_DEBUG) {
        log->log_level = NGX_LOG_DEBUG_ALL;
    }

    return NGX_CONF_OK;
}


static char *
ngx_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *value, name;

    if (cf->cycle->new_log.file) {
        return "is duplicate";
    }

    cf->cycle->new_log.fd = -1;//NLOG

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "stderr") == 0) {
        ngx_str_null(&name);

    } else {
        name = value[1];
    }

    cf->cycle->new_log.file = ngx_conf_open_file(cf->cycle, &name);
    if (cf->cycle->new_log.file == NULL) {
        return NULL;
    }

    if (cf->args->nelts == 2) {
        cf->cycle->new_log.log_level = NGX_LOG_ERR;
        return NGX_CONF_OK;
    }

    cf->cycle->new_log.log_level = 0;

    return ngx_log_set_levels(cf, &cf->cycle->new_log);
}

/*------------------------NLOG------------------------*/
//char *ngx_nlog(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
//{
//    ngx_str_t *value, localaddr, remoteaddress;
//    char*     pos;
//    char      rip[16] = {0};
//    int       val     = 1;
//    unsigned short lport,rport;
//    struct sockaddr_in laddr;
//
//    //need set file first
//    if (NULL == cf->cycle->new_log.file) {
//        return "need set error_log first";
//    }
//
//    value = cf->args->elts;
//
//    localaddr = value[1];
//    remoteaddress = value[2];
//
//    /* nlog 127.0.0.1:5050  192.168.0.25:5151 */
//    pos = strchr((char*)localaddr.data,':');
//    if (NULL == pos) {
//        return NGX_CONF_ERROR;
//    }
//    lport = (unsigned short)atoi(pos + 1);
//
//    pos = strchr((char*)remoteaddress.data,':');
//    if (NULL == pos) {
//        return NGX_CONF_ERROR;
//    }
//    rport = (unsigned short)atoi(pos + 1);
//
//    int len = pos - (char*)remoteaddress.data;
//    if (len <= 0 || len >= 16) {
//        return NGX_CONF_ERROR;
//    }
//
//    memcpy(rip,remoteaddress.data,len);
//    rip[len] = '\0';
//
//    //printf("local port:%u, remote port:%u, remote ip:%s\n",lport,rport,rip);
//
//    laddr.sin_family = AF_INET;
//     laddr.sin_port =  htons(lport);
//    laddr.sin_addr.s_addr = INADDR_ANY;
//
//      remoteaddr.sin_family = AF_INET;
//      remoteaddr.sin_port =  htons(rport);
//      remoteaddr.sin_addr.s_addr = inet_addr (rip);
//
//    if ((sock = socket (PF_INET, SOCK_DGRAM, 0)) < 0)
//    {
//        //perror("socket");
//        return NGX_CONF_ERROR;
//    }
//
//    //printf("sock %d\n",sock);
//
//    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &val, sizeof (val)) != 0)
//    {
//          //printf ("error!setsockopt failed! ");
//          return NGX_CONF_ERROR;
//    }
//
//    if (bind (sock, (struct sockaddr *) &laddr, sizeof (laddr)) < 0)
//    {
//        //perror("bind");
//        return NGX_CONF_ERROR;
//    }
//
//    return NGX_CONF_OK;
//}

char *ngx_nlog(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t              *value;
    ngx_url_t               u_l;
    ngx_url_t               u_r;
    ngx_socket_t            s;
    int                     reuseaddr;
    ngx_pool_cleanup_t     *cln;

    //need set file first
    if (NULL == cf->cycle->new_log.file) {
        return "need set error_log first";
    }
    
    if (cf->cycle->new_log.fd != -1) {
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
    
    cf->cycle->new_log.fd = s;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    cln->data = &cf->cycle->new_log;
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
    ngx_log_t  *log;

    log = data;
    if (log->fd != -1) {
        ngx_close_socket(log->fd);
        log->fd = -1;
    }
}
/*------------------------NLOG------------------------*/
