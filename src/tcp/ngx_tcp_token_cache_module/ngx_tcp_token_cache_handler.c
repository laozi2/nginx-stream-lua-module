#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_tcp.h>
#include "ngx_tcp_token_cache_module.h"

ngx_atomic_t *ngx_stat_token_req_cur_sec = NULL;

typedef ngx_int_t (*ngx_tcp_token_cache_cmd_pt)(ngx_tcp_session_t *s);

typedef struct{

    ngx_int_t cmd_id;
    ngx_tcp_token_cache_cmd_pt cmd_pt;

}ngx_tcp_token_cache_cmd;

#define ngx_tcp_cache_null_command  { 0, NULL }

static ngx_uint_t ngx_tcp_token_hash(u_char* str, size_t len, ngx_uint_t hash_slots_n);
static void ngx_tcp_token_spin_lock(ngx_shmtx_t *mtx);
static void ngx_tcp_token_spin_unlock(ngx_shmtx_t *mtx);
static void ngx_tcp_token_delete_token_locked(ngx_connection_t *c,ngx_tcp_token_slab_pool_t* pool, 
                                ngx_tcp_token_info_t **p_pre_token_node, 
                                ngx_tcp_token_info_t **p_cur_token_node, ngx_uint_t slot);

static ngx_int_t ngx_tcp_token_get_token_info(ngx_tcp_session_t *s);
static ngx_int_t ngx_tcp_token_set_token_info(ngx_tcp_session_t *s);
static ngx_int_t ngx_tcp_token_del_token_info(ngx_tcp_session_t *s);
static ngx_int_t ngx_tcp_token_token_status(ngx_tcp_session_t *s);
static ngx_int_t ngx_tcp_token_traverse(ngx_tcp_session_t *s);

static 
ngx_tcp_token_cache_cmd ngx_tcp_token_cache_cmds[] = {
    {100,ngx_tcp_token_get_token_info}, //higher frequency first
    {200,ngx_tcp_token_set_token_info},
    {300,ngx_tcp_token_del_token_info},
    {400,ngx_tcp_token_token_status},
    {500,ngx_tcp_token_traverse},
    ngx_tcp_cache_null_command
};

static ngx_uint_t
ngx_tcp_token_hash(u_char* str, size_t len, ngx_uint_t hash_slots_n)
{
    // BKDR Hash Function

    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;
 
    while (len--) {
        hash = hash * seed + (*str++);
    }
 
    return (hash & 0x7FFFFFFF)%hash_slots_n;
}

uint16_t
ngx_tcp_token_ntoint16(u_char* s)
{
    return ntohs(*(uint16_t*)s);
}

uint32_t
ngx_tcp_token_ntoint32(u_char* s)
{
    //uint32_t n;
    //memcpy(&n,s,4);
    //return ntohl(n);
    return ntohl(*(uint32_t*)s);
}

time_t
ngx_tcp_token_ntotimet(u_char* s)
{
//    uint32_t nl;
//
//    memcpy(&nl,s + 4,4);
//#if (NGX_PTR_SIZE == 4)
//    return ntohl(nl);
//#else
//    uint32_t nh;
//    memcpy(&nh,s,4);
//    return ntohl(nh) * (NGX_MAX_UINT32_VALUE + 1) + nl;
//#endif
    uint32_t high32;
    uint32_t low32;

    high32 = ntohl(*(uint32_t*)s);
    low32 = ntohl(*(uint32_t*)(s + 4));
#if (NGX_TIME_T_SIZE <= 4)
    if ( high32 > 0 ){
        //log warn : set high32 = 0
    }
    return low32;
#else
    return ( (uint64_t)high32 << 32 ) + low32;
#endif
}

void 
ngx_tcp_token_memcpy_int16ton(u_char* s,short n)
{
    uint16_t n_net = htons(n);
    memcpy(s,&n_net,2);
}

void 
ngx_tcp_token_memcpy_int32ton(u_char* s,int n)
{
//#if (NGX_HAVE_LITTLE_ENDIAN)
//    int i = 0;
//    for(i = 0;i < 4;i++){
//        *(s + 3 - i) = *((u_char*)p_n + i);
//    }
//#else
//    memcpy(s,p_n,4);
//#endif
    uint32_t n_net = htonl(n);
    memcpy(s,&n_net,4);
}

void 
ngx_tcp_token_memcpy_timetton(u_char* s,time_t n)
{
//#if (NGX_HAVE_LITTLE_ENDIAN)
//    int i = 0;
//    for(i = 0;i < 8;i++){
//        *(s + 7 - i) = *((u_char*)p_n + i);
//    }
//#else
//    memcpy(s,p_n,8);
//#endif
#if (NGX_TIME_T_SIZE <= 4)
    uint32_t n_net = htonl(n);
    memset(s,0,4);
    memcpy(s + 4,&n_net,4);
#else
    uint32_t n_net_high32 = htonl(n >> 32);
    uint32_t n_net_low32 = htonl(n & 0xffffffff);
    memcpy(s,&n_net_high32,4);
    memcpy(s + 4,&n_net_low32,4);
#endif
}

static void 
ngx_tcp_token_spin_lock(ngx_shmtx_t *mtx)
{
    //need NGX_HAVE_ATOMIC_OPS
    ngx_uint_t         i, n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");

    for ( ;; ) {

        if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
            return;
        }

        if (ngx_ncpu > 1) {

            for (n = 1; n < mtx->spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    ngx_cpu_pause();
                }

                if (*mtx->lock == 0
                    && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid))
                {
                    return;
                }
            }
        }

        ngx_sched_yield();
    }
}

static void 
ngx_tcp_token_spin_unlock(ngx_shmtx_t *mtx)
{
    //need NGX_HAVE_ATOMIC_OPS
    if (mtx->spin != (ngx_uint_t) -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
    }

    if (0 == ngx_atomic_cmp_set(mtx->lock, ngx_pid, 0)) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock failed");
    }
}

static void 
ngx_tcp_token_delete_token_locked(ngx_connection_t *c,ngx_tcp_token_slab_pool_t* pool, 
                    ngx_tcp_token_info_t **p_pre_token_node, 
                    ngx_tcp_token_info_t **p_cur_token_node, ngx_uint_t slot)
{
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "slot %ud[%*s][%ud][%T] removed", slot,
                                        NGX_TCP_TOKEN_LEN,(*p_cur_token_node)->token,
                                        (*p_cur_token_node)->user_id,
                                        (*p_cur_token_node)->expiry_time
                                    );
    
    //ngx_shmtx_lock(&pool->mutex);
    ngx_tcp_token_spin_lock(&pool->mutex);
    
    ngx_tcp_token_info_t *pre_token_node = *p_pre_token_node;
    ngx_tcp_token_info_t *cur_token_node = *p_cur_token_node;
    
    if( 0 == (cur_token_node->flag & NGX_TCP_TOKEN_FLAG_TOKEN_INUSE) ){
        if(pre_token_node == cur_token_node){
            pre_token_node = pool->hash_slots[slot];
            cur_token_node = pre_token_node;
        }
        else{
            cur_token_node = pre_token_node->next;
        }
        
        *p_pre_token_node = pre_token_node;
        *p_cur_token_node = cur_token_node;
        
        ngx_tcp_token_spin_unlock(&pool->mutex);
        return;
    }

    cur_token_node->flag &= (~NGX_TCP_TOKEN_FLAG_TOKEN_INUSE);

    if(pre_token_node == cur_token_node){
        pool->hash_slots[slot] = cur_token_node->next;
        
        cur_token_node->next = pool->free_token;
        pool->free_token = cur_token_node;
        ++pool->free_token_n;
        
        pre_token_node = pool->hash_slots[slot];
        cur_token_node = pre_token_node;
    }
    else{
        pre_token_node->next = cur_token_node->next;
        
        cur_token_node->next = pool->free_token;
        pool->free_token = cur_token_node;
        ++pool->free_token_n;
    
        cur_token_node = pre_token_node->next;
    }
    
    *p_pre_token_node = pre_token_node;
    *p_cur_token_node = cur_token_node;
    
    //statistics
    --pool->token_status.ngx_stat_token_number;
    
    //ngx_shmtx_unlock(&pool->mutex);
    ngx_tcp_token_spin_unlock(&pool->mutex);

}

//暂不区分，返回NULL的原因: token已经存在，还是没有空间
//新token放最后，为了检查过期和重复
ngx_tcp_token_info_t*
ngx_tcp_token_set_token(ngx_tcp_token_slab_pool_t* pool,ngx_connection_t *c,u_char* token)
{
    ngx_tcp_token_info_t* p_pool_token_info;
    ngx_tcp_token_info_t* pre_token_node, *cur_token_node;
    ngx_uint_t slot;
    time_t     now;
    //int        count = 0;
    
    p_pool_token_info = NULL;
    slot = ngx_tcp_token_hash(token,NGX_TCP_TOKEN_LEN,pool->hash_slots_n);
    pre_token_node = pool->hash_slots[slot];
    cur_token_node = pre_token_node;
    now = ngx_time();
    
    while(cur_token_node){
        //if( ++count > 100 ){
        //    break;
        //}

        //check expiry/repeat when get
        if(cur_token_node->expiry_time < now){
            ngx_tcp_token_delete_token_locked(c, pool,&pre_token_node, &cur_token_node,slot);
        }
        else{
            if(ngx_strncmp(token,cur_token_node->token,NGX_TCP_TOKEN_LEN) == 0){
                p_pool_token_info = cur_token_node;
            }
            pre_token_node = cur_token_node;
            cur_token_node = cur_token_node->next;
        }
    }
    
    if(p_pool_token_info){
        return p_pool_token_info;//or NULL;
    }
       
    //ngx_shmtx_lock(&pool->mutex);
    ngx_tcp_token_spin_lock(&pool->mutex);

    p_pool_token_info = pool->free_token;
    if(NULL == p_pool_token_info){
        //ngx_shmtx_unlock(&pool->mutex);
        ngx_tcp_token_spin_unlock(&pool->mutex);
        return NULL;
    }

    pool->free_token = pool->free_token->next;
    --pool->free_token_n;
    
    p_pool_token_info->flag |= NGX_TCP_TOKEN_FLAG_TOKEN_INUSE;
    p_pool_token_info->next = cur_token_node;
    if(pre_token_node){
        pre_token_node->next = p_pool_token_info;
    }
    else{
        pool->hash_slots[slot] = p_pool_token_info;
    }
    
    //statistics
    ++pool->token_status.ngx_stat_token_number;

    //ngx_shmtx_unlock(&pool->mutex);
    ngx_tcp_token_spin_unlock(&pool->mutex);
    
    return p_pool_token_info;
}

ngx_tcp_token_info_t*
ngx_tcp_token_get_token(ngx_tcp_token_slab_pool_t* pool,ngx_connection_t *c,u_char* token)
{
    ngx_tcp_token_info_t* p_pool_token_info;
    ngx_tcp_token_info_t* pre_token_node, *cur_token_node;
    ngx_uint_t slot;
    time_t     now;
    
    p_pool_token_info = NULL;
    slot = ngx_tcp_token_hash(token,NGX_TCP_TOKEN_LEN,pool->hash_slots_n);
    pre_token_node = pool->hash_slots[slot];
    cur_token_node = pre_token_node;
    now = ngx_time();
    
    while(cur_token_node){
        //check expiry when get
        //策略：优先检查过期，过期则删除，否则比较token, 暂不区分token不存在和过期
        if(cur_token_node->expiry_time < now){
            ngx_tcp_token_delete_token_locked(c, pool,&pre_token_node, &cur_token_node,slot);
        }
        else{
            if(ngx_strncmp(token,cur_token_node->token,NGX_TCP_TOKEN_LEN) == 0){
                p_pool_token_info = cur_token_node;
            }
            pre_token_node = cur_token_node;
            cur_token_node = cur_token_node->next;
        }
    }
    
    return p_pool_token_info;
}

void
ngx_tcp_token_delete_token(ngx_tcp_token_slab_pool_t* pool,ngx_connection_t *c,u_char* token)
{
    //ngx_tcp_token_info_t* p_pool_token_info;
    ngx_tcp_token_info_t* pre_token_node, *cur_token_node;
    ngx_uint_t slot;
    time_t     now;
    
    slot = ngx_tcp_token_hash(token,NGX_TCP_TOKEN_LEN,pool->hash_slots_n);
    
    pre_token_node = pool->hash_slots[slot];
    cur_token_node = pre_token_node;
    now = ngx_time();
    
    while(cur_token_node){ 
        //check expiry when delete
        //策略：优先检查过期，过期则删除，否则比较token, 暂不区分token不存在和过期
        if (cur_token_node->expiry_time < now) {
            ngx_tcp_token_delete_token_locked(c, pool,&pre_token_node, &cur_token_node,slot);
        }
        else if (ngx_strncmp(token,cur_token_node->token, NGX_TCP_TOKEN_LEN) == 0) {
            ngx_tcp_token_delete_token_locked(c, pool,&pre_token_node, &cur_token_node,slot);
        }
        else {
            pre_token_node = cur_token_node;
            cur_token_node = cur_token_node->next;
        }
    }
}

unsigned int
ngx_tcp_token_token_traverse(ngx_tcp_token_slab_pool_t* pool,ngx_connection_t *c, unsigned int* arr_hash_times)
{
    unsigned int               i,collision;
    unsigned int               removed_num = 0;
    time_t                     now;
    ngx_uint_t                 hash_slots_n;
    ngx_tcp_token_info_t     **hash_slots;
    ngx_tcp_token_info_t      *cur_token_node,*pre_token_node;

    now = ngx_time();
    hash_slots = (ngx_tcp_token_info_t**)pool->hash_slots;
    hash_slots_n = pool->hash_slots_n;

    for( i = 0; i < hash_slots_n; i++ ){
        collision = 0;
        pre_token_node = hash_slots[i];
        cur_token_node = pre_token_node;
    
        while(cur_token_node){
            //check link errors
            if(0 == (cur_token_node->flag & NGX_TCP_TOKEN_FLAG_TOKEN_INUSE)){
                pre_token_node->next = NULL;
                ngx_log_error(NGX_LOG_INFO, c->log, 0, "slot %ud not in use", i);
                
                break;
            }
            
            //check expiry/repeat when get
            if(cur_token_node->expiry_time < now){
                ngx_tcp_token_delete_token_locked(c, pool,&pre_token_node, &cur_token_node,i);
                ++removed_num;
            }
            else{
                pre_token_node = cur_token_node;
                cur_token_node = cur_token_node->next;
                ++collision;
            }
        }
        
        collision = (collision > 9) ? 9 : collision;
        ++arr_hash_times[collision];
    }

    return removed_num;
}

//----------------------------------
#define TC_LEN_HEADLEN 4
#define TC_LEN_CMD     2
#define TC_LEN_ERRNO   2
#define TC_LEN_REQID   4
#define TC_LEN_HEAD   (TC_LEN_HEADLEN + TC_LEN_CMD + TC_LEN_ERRNO + TC_LEN_REQID)
#define TC_LEN_STRLEN  4
#define TC_LEN_USERID  4
#define TC_LEN_EXPIRE  8

#define TC_POS_REQ_CMDID  0
#define TC_POS_REQ_ERRNO (TC_LEN_CMD + TC_POS_REQ_CMDID)
#define TC_POS_REQ_REQID (TC_LEN_ERRNO + TC_POS_REQ_ERRNO)
#define TC_POS_REQ_BODY  (TC_LEN_REQID + TC_POS_REQ_REQID)

#define TC_POS_RSP_CMDID (TC_LEN_HEADLEN)
#define TC_POS_RSP_ERRNO (TC_LEN_CMD + TC_POS_RSP_CMDID)
#define TC_POS_RSP_REQID (TC_LEN_ERRNO + TC_POS_RSP_ERRNO)
#define TC_POS_RSP_BODY  (TC_LEN_REQID + TC_POS_RSP_REQID)

ngx_int_t
ngx_tcp_token_protocal_handler(ngx_tcp_session_t *s)
{
    int                        i;
    uint16_t                   cmd_id;
    ngx_int_t                  error_code;
    time_t                     now;
    ngx_tcp_token_cache_session_ctx_t *ctx;
    ngx_tcp_token_slab_pool_t *pool;
    
    /*
        c-->s : [|-totoallen(4)-|,not in buffer]-cmd_id(2)-|-error_code(2)-|-request_id(4)-|-body-|-extra_data-|
        s-->c : 
    */
    
    ctx = s->ctx;
    pool = ctx->token_slab_pool;
    now = ngx_time();

    cmd_id = ngx_tcp_token_ntoint16(ctx->buffer_in->pos + TC_POS_REQ_CMDID);
    
    for(i = 0;ngx_tcp_token_cache_cmds[i].cmd_pt;i++){
        
        if(cmd_id == ngx_tcp_token_cache_cmds[i].cmd_id){
            
            error_code = ngx_tcp_token_cache_cmds[i].cmd_pt(s);
            
            //statistics
            if(NGX_TCP_CACHE_TOKEN_OK == error_code){
                if (pool->token_status.ngx_stat_cur_sec != now){
                    *ngx_stat_token_req_cur_sec = 0;
                    pool->token_status.ngx_stat_cur_sec = now;
                }
                (void) ngx_atomic_fetch_add(ngx_stat_token_req_cur_sec, 1);
                if(*ngx_stat_token_req_cur_sec > pool->token_status.ngx_stat_token_max_req_sec){
                    pool->token_status.ngx_stat_token_max_req_sec = *ngx_stat_token_req_cur_sec;
                }
            }

            return error_code;
        }
    }
    
    return NGX_TCP_CACHE_PROTOCOL_ERROR;
}



static ngx_int_t
ngx_tcp_token_get_token_info(ngx_tcp_session_t *s)
{
    int                        size;
    ngx_tcp_token_info_t      *token_info;
    short                      error_no;
    ngx_tcp_token_cache_session_ctx_t  *ctx;
    short                      respone_cmd_id = 101; 
    
    ctx = s->ctx;

    //body=2cmd+2error_code+4req_id+4strlen+24token+other
    #define TC_LEN_REQ100_MIN    (TC_LEN_CMD + TC_LEN_ERRNO + TC_LEN_REQID + TC_LEN_STRLEN + NGX_TCP_TOKEN_LEN)
    #define TC_POS_REQ100_TOKEN  (TC_POS_REQ_BODY + TC_LEN_STRLEN)
    #define TC_POS_RSP101_UID    (TC_POS_RSP_BODY)
    #define TC_POS_RSP101_EXPIRY (TC_LEN_USERID + TC_POS_RSP101_UID)
    
    if(ctx->body_len < TC_LEN_REQ100_MIN){
        return NGX_TCP_CACHE_PROTOCOL_ERROR;
    }
    
    token_info = ngx_tcp_token_get_token(ctx->token_slab_pool,s->connection,ctx->buffer_in->pos + TC_POS_REQ100_TOKEN);

    if(NULL == token_info){
        error_no = NGX_TCP_CACHE_TOKEN_NOT_FOUND;
        size = ctx->body_len - TC_LEN_REQ100_MIN + TC_LEN_HEAD;
        ctx->buffer_out = ngx_create_temp_buf(s->pool, size);
        if(ctx->buffer_out == NULL) {
            //ngx_log_error(NGX_LOG_ERROR, c->log,0,"wrong cmd_id \"%V\"",cmd_id);
            return NGX_TCP_CACHE_INTERNAL_ERROR;
        }
        
        ngx_tcp_token_memcpy_int32ton(ctx->buffer_out->last,size);
        ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_CMDID,respone_cmd_id);
        ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_ERRNO,error_no);
        memcpy(ctx->buffer_out->last + TC_POS_RSP_REQID,ctx->buffer_in->pos + TC_POS_REQ_REQID,TC_LEN_REQID);
        memcpy(ctx->buffer_out->last + TC_POS_RSP_BODY,ctx->buffer_in->pos + TC_LEN_REQ100_MIN,ctx->body_len - TC_LEN_REQ100_MIN);

        ctx->buffer_out->last += size;
        
        return NGX_TCP_CACHE_TOKEN_OK;
    }
    
    error_no = NGX_TCP_CACHE_TOKEN_OK;
    size = ctx->body_len - TC_LEN_REQ100_MIN + TC_LEN_HEAD + TC_LEN_USERID + TC_LEN_EXPIRE;
    
    ctx->buffer_out = ngx_create_temp_buf(s->pool, size);
    if(ctx->buffer_out == NULL) {
        //ngx_log_error(NGX_LOG_ERROR, c->log,0,"wrong cmd_id \"%V\"",cmd_id);
        return NGX_TCP_CACHE_INTERNAL_ERROR;
    }
    
    ngx_tcp_token_memcpy_int32ton(ctx->buffer_out->last,size);
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_CMDID,respone_cmd_id);
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_ERRNO,error_no);
    memcpy(ctx->buffer_out->last + TC_POS_RSP_REQID,ctx->buffer_in->pos + TC_POS_REQ_REQID,TC_LEN_REQID);
    ngx_tcp_token_memcpy_int32ton(ctx->buffer_out->last + TC_POS_RSP101_UID,(int)token_info->user_id);
    ngx_tcp_token_memcpy_int32ton(ctx->buffer_out->last + TC_POS_RSP101_EXPIRY,token_info->expiry_time);
    memcpy(ctx->buffer_out->last + TC_POS_RSP101_EXPIRY + TC_LEN_EXPIRE,ctx->buffer_in->pos + TC_LEN_REQ100_MIN,ctx->body_len - TC_LEN_REQ100_MIN);

    ctx->buffer_out->last += size;
    
    return NGX_TCP_CACHE_TOKEN_OK;
}


static ngx_int_t
ngx_tcp_token_set_token_info(ngx_tcp_session_t *s)
{
    int                        size;
    ngx_tcp_token_info_t      *token_info;
    int                        error_no;
    ngx_tcp_token_cache_session_ctx_t  *ctx;
    short                      respone_cmd_id = 201; 
    
    ctx = s->ctx;

    //2cmd+2error_code+4req_id+strlen(4)+token(24)+user_id(4)+time_expiry(8)+other
    #define TC_LEN_REQ200_MIN    (TC_LEN_CMD + TC_LEN_ERRNO + TC_LEN_REQID + TC_LEN_STRLEN + NGX_TCP_TOKEN_LEN + TC_LEN_USERID + TC_LEN_EXPIRE)
    #define TC_POS_REQ200_TOKEN  (TC_POS_REQ_BODY + TC_LEN_STRLEN)
    #define TC_POS_REQ200_UID    (TC_POS_REQ200_TOKEN + NGX_TCP_TOKEN_LEN)
    #define TC_POS_REQ200_EXPIRY (TC_POS_REQ200_UID + TC_LEN_USERID)
    #define TC_POS_RSP201_EXTRADATA (TC_POS_RSP_BODY)

    if(ctx->body_len < TC_LEN_REQ200_MIN){
        return NGX_TCP_CACHE_PROTOCOL_ERROR;
    }
    
    size = ctx->body_len - TC_LEN_REQ200_MIN + TC_LEN_HEAD;
    ctx->buffer_out = ngx_create_temp_buf(s->pool, size);
    if(ctx->buffer_out == NULL) {
        //ngx_log_error(NGX_LOG_ERROR, c->log,0,"wrong cmd_id \"%V\"",cmd_id);
        return NGX_TCP_CACHE_INTERNAL_ERROR;
    }

    //no care token will set is expired aleady
    token_info = ngx_tcp_token_set_token(ctx->token_slab_pool,s->connection,ctx->buffer_in->pos + TC_POS_REQ200_TOKEN);
    if(NULL == token_info){
        ngx_log_error(NGX_LOG_ALERT, s->connection->log,0,"[emergency] no more space");
        error_no = NGX_TCP_CACHE_NO_MORE_SPACE;
    }
    else{
        error_no = NGX_TCP_CACHE_TOKEN_OK;
        memcpy(token_info->token,ctx->buffer_in->pos + TC_POS_REQ200_TOKEN,NGX_TCP_TOKEN_LEN);
        token_info->user_id = ngx_tcp_token_ntoint32(ctx->buffer_in->pos + TC_POS_REQ200_UID);
        token_info->expiry_time = ngx_tcp_token_ntotimet(ctx->buffer_in->pos + TC_POS_REQ200_EXPIRY);

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "set [%*s][%ud][%T]",
                                        NGX_TCP_TOKEN_LEN,token_info->token,
                                        token_info->user_id,
                                        token_info->expiry_time
                                    );
    }
    
    ngx_tcp_token_memcpy_int32ton(ctx->buffer_out->last,size);
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_CMDID,respone_cmd_id);
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_ERRNO,error_no);
    memcpy(ctx->buffer_out->last + TC_POS_RSP_REQID,ctx->buffer_in->pos + TC_POS_REQ_REQID,TC_LEN_REQID);
    memcpy(ctx->buffer_out->last + TC_POS_RSP201_EXTRADATA,ctx->buffer_in->pos + TC_LEN_REQ200_MIN,ctx->body_len - TC_LEN_REQ200_MIN);

    ctx->buffer_out->last += size;
    
    return NGX_TCP_CACHE_TOKEN_OK;
}

static ngx_int_t
ngx_tcp_token_del_token_info(ngx_tcp_session_t *s)
{
    int                          size;
    //ngx_tcp_token_info_t      *token_info;
    int                          error_no;
    ngx_tcp_token_cache_session_ctx_t  *ctx;
    short                       respone_cmd_id = 301; 
    
    ctx = s->ctx;

    //2cmd+2error_code+4req_id+strlen(4)+token(24)+other
    #define TC_LEN_REQ300_MIN    (TC_LEN_CMD + TC_LEN_ERRNO + TC_LEN_REQID + TC_LEN_STRLEN + NGX_TCP_TOKEN_LEN)
    #define TC_POS_REQ300_TOKEN  (TC_POS_REQ_BODY + TC_LEN_STRLEN)
    #define TC_POS_RSP301_EXTRADATA (TC_POS_RSP_BODY)
    
    if(ctx->body_len < TC_LEN_REQ300_MIN){
        return NGX_TCP_CACHE_PROTOCOL_ERROR;
    }
    
    size = ctx->body_len - TC_LEN_REQ300_MIN + TC_LEN_HEAD;
    ctx->buffer_out = ngx_create_temp_buf(s->pool, size);
    if(ctx->buffer_out == NULL) {
        //ngx_log_error(NGX_LOG_ERROR, c->log,0,"wrong cmd_id \"%V\"",cmd_id);
        return NGX_TCP_CACHE_INTERNAL_ERROR;
    }

    ngx_tcp_token_delete_token(ctx->token_slab_pool,s->connection,ctx->buffer_in->pos + TC_POS_REQ300_TOKEN);
    error_no = NGX_TCP_CACHE_TOKEN_OK;
    
    ngx_tcp_token_memcpy_int32ton(ctx->buffer_out->last,size);
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_CMDID,respone_cmd_id);
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_ERRNO,error_no);
    memcpy(ctx->buffer_out->last + TC_POS_RSP_REQID,ctx->buffer_in->pos + TC_POS_REQ_REQID,TC_LEN_REQID);
    memcpy(ctx->buffer_out->last + TC_POS_RSP301_EXTRADATA,ctx->buffer_in->pos + TC_LEN_REQ300_MIN,ctx->body_len - TC_LEN_REQ300_MIN);

    ctx->buffer_out->last += size;
    
    return NGX_TCP_CACHE_TOKEN_OK;
}


static ngx_int_t
ngx_tcp_token_token_status(ngx_tcp_session_t *s)
{
    int                        size;
    int                        error_no;
    ngx_tcp_token_cache_session_ctx_t  *ctx;
    ngx_tcp_token_status_t    *p_token_status;
    short                       respone_cmd_id = 401; 
    
    ctx = s->ctx;
    p_token_status = &ctx->token_slab_pool->token_status;

    //2cmd+2error_code+4req_id+other
    #define TC_LEN_REQ400    (TC_LEN_CMD + TC_LEN_ERRNO + TC_LEN_REQID)

    if(ctx->body_len != TC_LEN_REQ400){
        return NGX_TCP_CACHE_PROTOCOL_ERROR;
    }

    size = sizeof("Requests in current second:  \n") + NGX_ATOMIC_T_LEN
           + sizeof("Max requests in one second:  \n") + NGX_INT64_LEN
           + sizeof("Number of tokens in share memory:  \n") + NGX_INT64_LEN
           + TC_LEN_HEAD;

    ctx->buffer_out = ngx_create_temp_buf(s->pool, size);
    if (ctx->buffer_out == NULL) {
        return NGX_TCP_CACHE_INTERNAL_ERROR;
    }
    
    error_no = 0;
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_CMDID,respone_cmd_id);
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_ERRNO,error_no);
    memcpy(ctx->buffer_out->last + TC_POS_RSP_REQID,ctx->buffer_in->pos + TC_POS_REQ_REQID,TC_LEN_REQID);

    ctx->buffer_out->last += TC_LEN_HEAD;
    
    ctx->buffer_out->last = ngx_sprintf(ctx->buffer_out->last, "Requests in current second: %uA \n", p_token_status->ngx_stat_token_req_cur_sec0);
    ctx->buffer_out->last = ngx_sprintf(ctx->buffer_out->last, "Max requests in one second: %ul \n", p_token_status->ngx_stat_token_max_req_sec);
    ctx->buffer_out->last = ngx_sprintf(ctx->buffer_out->last, "Number of tokens in share memory: %ul \n", p_token_status->ngx_stat_token_number);
    size = ctx->buffer_out->last - ctx->buffer_out->pos;
    ngx_tcp_token_memcpy_int32ton(ctx->buffer_out->pos,size);

    return NGX_TCP_CACHE_TOKEN_OK;
}

static ngx_int_t
ngx_tcp_token_traverse(ngx_tcp_session_t *s)
{
    unsigned int               size,i,removed_num = 0;
    int                        error_no;
    unsigned int               hash_times[10] = {0};
    ngx_uint_t                 hash_slots_n;
    ngx_tcp_token_cache_session_ctx_t  *ctx;
    short                       respone_cmd_id = 501; 
    
    ctx = s->ctx;
    hash_slots_n = ctx->token_slab_pool->hash_slots_n;

    //2cmd+2error_code+4req_id+other
    #define TC_LEN_REQ500    (TC_LEN_CMD + TC_LEN_ERRNO + TC_LEN_REQID)

    if(ctx->body_len != TC_LEN_REQ500){
        return NGX_TCP_CACHE_PROTOCOL_ERROR;
    }

    removed_num = ngx_tcp_token_token_traverse(ctx->token_slab_pool,s->connection,hash_times);

    /*
        removed tokens :  \n
        slots :  \n
        hash N times : 13424,0.032%\n  //N: 0-10
    */
    size = 512;

    ctx->buffer_out = ngx_create_temp_buf(s->pool, size);
    if (ctx->buffer_out == NULL) {
        return NGX_TCP_CACHE_INTERNAL_ERROR;
    }
    
    error_no = 0;
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_CMDID,respone_cmd_id);
    ngx_tcp_token_memcpy_int16ton(ctx->buffer_out->last + TC_POS_RSP_ERRNO,error_no);
    memcpy(ctx->buffer_out->last + TC_POS_RSP_REQID,ctx->buffer_in->pos + TC_POS_REQ_REQID,TC_LEN_REQID);

    ctx->buffer_out->last += TC_LEN_HEAD;
    
    ctx->buffer_out->last = ngx_sprintf(ctx->buffer_out->last, "removed tokens : %ud\n", removed_num);
    ctx->buffer_out->last = ngx_sprintf(ctx->buffer_out->last, "slots : %ud \n", hash_slots_n);
    for (i = 0; i < 9; i++){
        ctx->buffer_out->last = ngx_sprintf(ctx->buffer_out->last, "hash %d times : %ud, %.3f%%\n", i, hash_times[i], (double)hash_times[i]/hash_slots_n);
    }
    ctx->buffer_out->last = ngx_sprintf(ctx->buffer_out->last, "hash >%d times : %ud, %.3f%%\n", i, hash_times[i], (double)hash_times[i]/hash_slots_n);

    size = ctx->buffer_out->last - ctx->buffer_out->pos;
    ngx_tcp_token_memcpy_int32ton(ctx->buffer_out->pos,size);

    return NGX_TCP_CACHE_TOKEN_OK;
}
