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
#include "pb_format.h"
#include "protobuf_api.h"

protobuf_main_t protobuf_main;

int connect_server (protobuf_main_t * pbm, u8 * serverip, u16 port, u8 is_ipv6)
{
	char * address;

	address = (char*) format (0, "%U%c", (is_ipv6)?format_ip6_address:format_ip4_address, serverip, 0);
	clib_warning("Connecting to server %s on port %d ...", address, port);
	vec_free (address);

	memcpy (pbm->address, serverip, (is_ipv6)?16:4);
	pbm->port = port;
	pbm->is_ipv6 = is_ipv6;

    return 0;
}

int disconnect_server (protobuf_main_t * pbm)
{
	if (pbm && pbm->client)
	{
		protobuf_client_disconnect(pbm->client);
		memset (pbm->address, 0, 16 * sizeof (u8));
		pbm->port = 0;
	    return 0;
	}
    return 1;
}

static void *pb_alloc(void *allocator_data, size_t size)
{
    return clib_mem_alloc(size);
}

static void pb_free(void *allocator_data, void *data)
{
    clib_mem_free(data);
}

clib_error_t *
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
    clib_error_t * error = 0;
    clib_warning("Plugin register");

    return error;
}

#define HOSTNAME "localhost"
#define PORT    8335

static void protobuf_thread_fn (void *arg)
{
    char * hostname;

    while(1)
    {
    	hostname = (char*) format (0, "%U%c", (protobuf_main.is_ipv6)?format_ip6_address:format_ip4_address, protobuf_main.address, 0);
    	protobuf_main.client = protobuf_tcp_connect(protobuf_main.client, (const char*)hostname, protobuf_main.port);
        if (protobuf_main.client != NULL) {
        	// TODO
        	memcpy(protobuf_main.client->address, protobuf_main.address, 16);

            clib_warning("Connected to client %s:%d", hostname, protobuf_main.client->port);
            // start processing events while any watcher is active
            ev_run(protobuf_main.ev_loop, 0);
        }
        vec_free (hostname);
        // if client is not connected or it disconnected
        clib_warning("Retry..");
        sleep(3);
    }
    protobuf_client_free(protobuf_main.client);
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
    protobuf_main.allocator.alloc = &pb_alloc;
    protobuf_main.allocator.free = &pb_free;
    protobuf_main.allocator.allocator_data = NULL;
    protobuf_main.ev_loop = ev_default_loop(0);

    clib_warning("Init");
    protobuf_main.port = 0;
    protobuf_main.client = NULL;
    protobuf_main.is_ipv6 = 0;
	memset (protobuf_main.address, 0, 16 * sizeof (u8));

    protobuf_main_t * pbm = &protobuf_main;
    clib_error_t * error = protobuf_plugin_api_hookup (vm, pbm);    
    
    return 0;
}

VLIB_INIT_FUNCTION (protobuf_init);


