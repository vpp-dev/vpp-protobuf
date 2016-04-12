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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ev.h>
#include "tcpclient.h"
#include "vppprotobuf.h"

protobuf_main_t protobuf_main;

clib_error_t *
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
    clib_error_t * error = 0;
    clib_warning("plugin register");

    return error;
}

#define HOSTNAME "localhost"
#define PORT    8335

static void protobuf_thread_fn (void *arg)
{
    protobuf_main.ev_loop = ev_default_loop(0);
    protobuf_client_t *client = NULL;

    while(1)
    {
        client = protobuf_tcp_connect(client, HOSTNAME, PORT);
        if (client != NULL) {
            clib_warning("Connected to client %s:%d", client->address, client->port);
            // start processing events while any watcher is active
            ev_run(protobuf_main.ev_loop, 0);
        }
        // if client is not connected or it disconnected
        clib_warning("Retry..");
        sleep(3);
    }
    free(client);
}


VLIB_REGISTER_THREAD (protobuf_thread_reg, static) = {
    .name = "protobuf",
    .function = protobuf_thread_fn,
    .fixed_count = 1,
    .count = 1,
    .no_data_structure_clone = 1,
    .use_pthreads = 1,
    .mheap_size = 2<<20,
};

static clib_error_t * protobuf_init (vlib_main_t * vm)
{
    clib_warning("init");
    return 0;
}

VLIB_INIT_FUNCTION (protobuf_init);


