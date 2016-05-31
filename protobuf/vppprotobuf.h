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
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include "tcpclient.h"

typedef struct {
    /* input queue */
    unix_shared_memory_queue_t * vl_input_queue;

    /* errors by number */
    uword * error_string_by_error_number;

    /* interface name table */
    uword * sw_if_index_by_interface_name;

    /* routes destination map */
    uword * ipv4_hops_by_destination_addr_table;
    uword * ipv6_hops_by_destination_addr_table;

    /*
     * All VLIB-side message handlers use my_client_index to identify
     * the queue / client. This works in sim replay.
     */
    int my_client_index;

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

    u8 reconnect_to_vpe;

    u8 hostname[128];
    int port;
    protobuf_client_t *client;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
} protobuf_main_t;

typedef union {
  u8 as_u8[4];
  u32 as_32;
} ipv4_address_t;

typedef union {
  u8 as_u8[16];
  u32 as_u32[4];
} ipv6_address_t;

typedef struct {
  ipv4_address_t address;
  u32 prefix;
} ipv4_destination_t;

typedef struct {
  ipv6_address_t address;
  u32 prefix;
} ipv6_destination_t;

extern protobuf_main_t protobuf_main;

int connect_server (protobuf_main_t * pbm, u8 * serverip, u16 port, u8 is_ipv6);
int disconnect_server (protobuf_main_t * pbm);

static inline f64 protobuf_time_now (protobuf_main_t *pbm)
{
    return clib_time_now (&pbm->clib_time);
}

void protobuf_api_hookup (protobuf_main_t *pbm);
int protobuf_interface_dump (protobuf_main_t *pbm);

#endif
