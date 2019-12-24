
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_queue_t  ngx_posted_accept_events;
ngx_queue_t  ngx_posted_next_events;
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

        //自队列中移除event
        ngx_delete_posted_event(ev);

        //event处理
        ev->handler(ev);
    }
}


void
ngx_event_process_posted_next(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    while (!ngx_queue_empty(posted)) {

        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        ngx_delete_posted_event(ev);

        if (!ev->ready) {
            ev->ready = 1;
            ev->available = -1;
        }

        ev->handler(ev);
    }
}
