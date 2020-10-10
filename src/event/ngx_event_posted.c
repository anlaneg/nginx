
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/*accept事件队列*/
ngx_queue_t  ngx_posted_accept_events;
/*中间队列，放在此队列中的元素，会被移动到ngx_posted_events队列*/
ngx_queue_t  ngx_posted_next_events;
/*非accept事件队列*/
ngx_queue_t  ngx_posted_events;


//处理队列中event
void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    //处理posted队列中所有event
    while (!ngx_queue_empty(posted)) {

    		//取队列中有event
        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        //自队列中移除此event
        ngx_delete_posted_event(ev);

        //event处理
        ev->handler(ev);
    }
}

/*将next_event所有元素移至ngx_posted_events*/
void
ngx_event_move_posted_next(ngx_cycle_t *cycle)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    /*遍历ngx_posted_next_events队列中所有元素，更新ready=1*/
    for (q = ngx_queue_head(&ngx_posted_next_events);
         q != ngx_queue_sentinel(&ngx_posted_next_events);
         q = ngx_queue_next(q))
    {
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        ev->ready = 1;
        ev->available = -1;
    }

    /*将ngx_posted_next_events中的所有元素，合并到ngx_posted_events中*/
    ngx_queue_add(&ngx_posted_events, &ngx_posted_next_events);
    /*重新初始化next_event*/
    ngx_queue_init(&ngx_posted_next_events);
}
