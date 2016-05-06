/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __VPPPROTOBUF__H__
#define __VPPPROTOBUF__H__

#include <setjmp.h>
#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <ev.h>
#include <vppinfra/error.h>
#include "vpp.pb-c.h"

typedef struct {
    /* input queue */
    unix_shared_memory_queue_t * vl_input_queue;
    /*
     * All VLIB-side message handlers use my_client_index to identify 
     * the queue / client. This works in sim replay.
     */
    int my_client_index;
    /*
     * This is the (shared VM) address of the registration,
     * don't use it to id the connection since it can't possibly
     * work in simulator replay.
     */
    vl_api_registration_t *my_registration;

    u8 rx_thread_jmpbuf_valid;
    u8 connected_to_vlib;
    jmp_buf rx_thread_jmpbuf;
    pthread_t rx_thread_handle;

    /* Main thread can spin (w/ timeout) here if needed */
    u32 async_mode;
    u32 async_errors;
    volatile u32 result_ready;
    volatile i32 retval;
    volatile u8 *shmem_result;

    /* Time is of the essence... */
    clib_time_t clib_time;

    /* libev loop */
    struct ev_loop *ev_loop;
    /* protobuf allocator */
    ProtobufCAllocator allocator;

    /* context variables */
    u8 *vpp_version;
} protobuf_main_t;

extern protobuf_main_t protobuf_main;

static inline f64 protobuf_time_now (protobuf_main_t *pbm)
{
    return clib_time_now (&pbm->clib_time);
}
void protobuf_api_hookup (protobuf_main_t *pbm);

#endif

