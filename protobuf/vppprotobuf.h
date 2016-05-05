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

#include <ev.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include "vpp.pb-c.h"
#include "tcpclient.h"

typedef struct {
    struct ev_loop *ev_loop;
    ProtobufCAllocator allocator;

    u8 is_ipv6;
    u8 address[16];
    int port;
    protobuf_client_t *client;

    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
} protobuf_main_t;

extern protobuf_main_t protobuf_main;

int connect_server (protobuf_main_t * pbm, u8 * serverip, u16 port, u8 is_ipv6);
int disconnect_server (protobuf_main_t * pbm);

#endif

