
/*
 * Copyright (C)
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>


static void *ngx_tcp_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_tcp_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_tcp_core_pool_size(ngx_conf_t *cf, void *post, void *data);
static char *ngx_tcp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static char *ngx_nlog(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_tcp_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static char *ngx_tcp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_clean_nlog_sock(void* data);

static ngx_conf_post_handler_pt  ngx_tcp_core_pool_size_p =
    ngx_tcp_core_pool_size;


static ngx_command_t  ngx_tcp_core_commands[] = {

    { ngx_string("server"),
      NGX_TCP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_tcp_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_tcp_core_listen,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("protocol"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_core_protocol,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("read_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, read_timeout),
      NULL },
      
    { ngx_string("send_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, send_timeout),
      NULL },

    { ngx_string("keepalive_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, keepalive_timeout),
      NULL },
    
    { ngx_string("session_pool_size"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, session_pool_size),
      &ngx_tcp_core_pool_size_p },
      
    { ngx_string("connection_pool_size"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, connection_pool_size),
      &ngx_tcp_core_pool_size_p },
     
    { ngx_string("client_max_body_size"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, client_max_body_size),
      NULL },
      
    { ngx_string("error_log"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_tcp_core_error_log,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("nlog"),
     NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE2,
     ngx_nlog,
     NGX_TCP_SRV_CONF_OFFSET,
     0,
     NULL},

    { ngx_string("allow"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_access_rule,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("deny"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_access_rule,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("resolver"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_tcp_core_resolver,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("resolver_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, resolver_timeout),
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_core_module_ctx = {
    NULL,                                  /* protocol */
    NULL,                                  /*  postconfiguration */

    ngx_tcp_core_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_tcp_core_create_srv_conf,         /* create server configuration */
    ngx_tcp_core_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_tcp_core_module = {
    NGX_MODULE_V1,
    &ngx_tcp_core_module_ctx,             /* module context */
    ngx_tcp_core_commands,                /* module directives */
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


static void *
ngx_tcp_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_tcp_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_tcp_listen_t))
        != NGX_OK)
    {
        return NULL;
    }

    return cmcf;
}


static void *
ngx_tcp_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->protocol = NULL;
     *     cscf->error_log = NULL;
     *     cscf->log_handler = NULL;
     *     cscf->rules = NULL;
     */

    cscf->read_timeout = NGX_CONF_UNSET_MSEC;
    cscf->send_timeout = NGX_CONF_UNSET_MSEC;
    cscf->keepalive_timeout = NGX_CONF_UNSET_MSEC;
    cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    cscf->so_keepalive = NGX_CONF_UNSET;
    cscf->session_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->client_max_body_size = NGX_CONF_UNSET_SIZE;
    cscf->resolver = NGX_CONF_UNSET_PTR;

    //cscf->file_name = cf->conf_file->file.name.data;
    //cscf->line = cf->conf_file->line;

    return cscf;
}


static char *
ngx_tcp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_tcp_core_srv_conf_t *prev = parent;
    ngx_tcp_core_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->read_timeout, prev->read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
    ngx_conf_merge_msec_value(conf->keepalive_timeout, prev->keepalive_timeout, NGX_CONF_UNSET_MSEC);
    ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout, 30000);

    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);

    ngx_conf_merge_size_value(conf->session_pool_size,
                              prev->session_pool_size, 1024);//default 1k
    ngx_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 512);//default 0.5k
    ngx_conf_merge_size_value(conf->client_max_body_size,
                              prev->client_max_body_size, 1024);//default 1k


    if (conf->protocol == NULL) {
        //ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
        //              "unknown tcp protocol for server in %s:%ui",
        //              conf->file_name, conf->line);
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,"no tcp protocol for server");
        return NGX_CONF_ERROR;
    }
    
    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }

    if (conf->resolver == NGX_CONF_UNSET_PTR) {

        if (prev->resolver == NGX_CONF_UNSET_PTR) {

            /*
             * create dummy resolver in tcp {} context
             * to inherit it in all servers
             */

            prev->resolver = ngx_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }


    return NGX_CONF_OK;
}


static char *
ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_tcp_module_t          *module;
    ngx_tcp_conf_ctx_t        *ctx, *tcp_ctx;
    ngx_tcp_core_srv_conf_t   *cscf, **cscfp;
    ngx_tcp_core_main_conf_t  *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    tcp_ctx = cf->ctx;
    ctx->main_conf = tcp_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_tcp_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_tcp_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_TCP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == NGX_CONF_OK && !cscf->listen) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                              "server{ need command 'listen'");
        return NGX_CONF_ERROR;
    }

    return rv;
}


static char *
ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t    *cscf = conf;

    size_t                      len, off;
    in_port_t                   port;
    ngx_str_t                  *value,size;
    ngx_url_t                   u;
    ngx_uint_t                  i;
    struct sockaddr            *sa;
    ngx_tcp_listen_t          *lsopt;
    struct sockaddr_in         *sin;
    ngx_tcp_core_main_conf_t  *cmcf;

    cscf->listen = 1;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);

    lsopt = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = (struct sockaddr *) lsopt[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

        //no care NGX_HAVE_INET6/NGX_HAVE_UNIX_DOMAIN

        default: /* AF_INET */
            off = offsetof(struct sockaddr_in, sin_addr);
            len = 4;
            sin = (struct sockaddr_in *) sa;
            port = htons(sin->sin_port);
            break;
        }

        if (ngx_memcmp(lsopt[i].sockaddr + off, u.sockaddr + off, len) != 0) {
            //continue;/*暂时严格端口不重复*/
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    lsopt = ngx_array_push(&cmcf->listen);
    if (lsopt == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(lsopt, sizeof(ngx_tcp_listen_t));

    ngx_memcpy(lsopt->sockaddr, u.sockaddr, u.socklen);

    lsopt->socklen = u.socklen;
    lsopt->wildcard = u.wildcard;
    lsopt->ctx = cf->ctx;
    lsopt->backlog = NGX_LISTEN_BACKLOG;
    lsopt->rcvbuf = -1;
    lsopt->sndbuf = -1;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            lsopt->bind = 1;
            continue;
        }
        
        if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
            lsopt->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
            lsopt->bind = 1;

            if (lsopt->backlog == NGX_ERROR || lsopt->backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            lsopt->rcvbuf = ngx_parse_size(&size);
            lsopt->bind = 1;

            if (lsopt->rcvbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "sndbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            lsopt->sndbuf = ngx_parse_size(&size);
            lsopt->bind = 1;

            if (lsopt->sndbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (ngx_strcmp(&value[i].data[13], "on") == 0) {
                lsopt->so_keepalive = 1;

            } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
                lsopt->so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt->tcp_keepidle = ngx_parse_time(&s, 1);
                    if (lsopt->tcp_keepidle == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt->tcp_keepintvl = ngx_parse_time(&s, 1);
                    if (lsopt->tcp_keepintvl == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    lsopt->tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if (lsopt->tcp_keepcnt == NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (lsopt->tcp_keepidle == 0 && lsopt->tcp_keepintvl == 0
                    && lsopt->tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                lsopt->so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            lsopt->bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return NGX_CONF_ERROR;
#endif
        }
        
        if (ngx_strcmp(value[i].data, "deferred") == 0) {
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            lsopt->deferred_accept = 1;
            lsopt->bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the deferred accept is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_tcp_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t  *cscf = conf;

    ngx_str_t          *value;
    ngx_uint_t          m;
    ngx_tcp_module_t  *module;
    
    if(NULL != cscf->protocol) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "duplicate protocol");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->protocol
            && ngx_strcmp(module->protocol->name.data, value[1].data) == 0)
        {
            cscf->protocol = module->protocol;
            module->protocol->set = NGX_TCP_PROTOCOL_SET;

            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown protocol \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}


static char *
ngx_tcp_core_pool_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_MIN_POOL_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           NGX_MIN_POOL_SIZE);
        return NGX_CONF_ERROR;
    }

    if (*sp % NGX_POOL_ALIGNMENT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           NGX_POOL_ALIGNMENT);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_tcp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t *cscf = conf;

    ngx_str_t  *value, name;

    if (cscf->error_log) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "stderr") == 0) {
        ngx_str_null(&name);

    } else {
        name = value[1];
    }

    cscf->error_log = ngx_log_create(cf->cycle, &name);
    if (cscf->error_log == NULL) {
        return NGX_CONF_ERROR;
    }

    cscf->error_log->fd = -1;

    if (cf->args->nelts == 2) {
        cscf->error_log->log_level = NGX_LOG_ERR;
        return NGX_CONF_OK;
    }

    return ngx_log_set_levels(cf, cscf->error_log);
}

static char *
ngx_tcp_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_core_srv_conf_t *cscf = conf;

    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t               cidr;
    ngx_tcp_access_rule_t   *rule;

    if (cscf->rules == NULL) {
        cscf->rules = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_tcp_access_rule_t));
        if (cscf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(cscf->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    rule->deny = (value[0].data[0] == 'd') ? 1 : 0;

    if (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0) {
        rule->mask = 0;
        rule->addr = 0;

        return NGX_CONF_OK;
    }

    rc = ngx_ptocidr(&value[1], &cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cidr.family != AF_INET) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"allow\" supports IPv4 only");
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    rule->mask = cidr.u.in.mask;
    rule->addr = cidr.u.in.addr;

    return NGX_CONF_OK;
}

static char *
ngx_tcp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_core_srv_conf_t  *cscf = conf;
    ngx_str_t                *value;

    value = cf->args->elts;

    if (cscf->resolver != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        cscf->resolver = NGX_CONF_UNSET_PTR;
        return NGX_CONF_OK;
    }

    cscf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}



char *ngx_nlog(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t               *value;
    ngx_url_t                u_l;
    ngx_url_t                u_r;
    ngx_socket_t             s;
    int                      reuseaddr;
    ngx_pool_cleanup_t      *cln;
    ngx_tcp_core_srv_conf_t *cscf = conf;

    //need set file first
    if (NULL == cscf->error_log) {
        return "need set error_log first";
    }
    
    if (cscf->error_log->fd != -1) {
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

    if (bind(s, (struct sockaddr_in*) &u_l.sockaddr, u_l.socklen) == -1)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bind() failed, %d", ngx_socket_errno);

        goto failed;
    }
    
    if (connect(s, (struct sockaddr_in*) &u_r.sockaddr, u_r.socklen) == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "connect() failed, %d", ngx_socket_errno);

        goto failed;
    }
    
    cscf->error_log->fd = s;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    cln->data = cscf->error_log;
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
    }
}
