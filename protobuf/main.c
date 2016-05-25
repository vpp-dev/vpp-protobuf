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
#include "vppprotobuf.h"

protobuf_main_t protobuf_main;

static void *pb_alloc(void *allocator_data, size_t size)
{
    return clib_mem_alloc(size);
}

static void pb_free(void *allocator_data, void *data)
{
    clib_mem_free(data);
}

static int connect_to_vpe(char *name)
{
    protobuf_main_t * pbm = &protobuf_main;
    api_main_t * am = &api_main;

    if (vl_client_connect_to_vlib("/vpe-api", name, 32) < 0)
        return -1;
    
    pbm->vl_input_queue = am->shmem_hdr->vl_input_queue;
    pbm->my_client_index = am->my_client_index;

    return 0;
}

int connect_server (protobuf_main_t * pbm, u8 * serverip, u16 port, u8 is_ipv6)
{
	memcpy (pbm->hostname, serverip, vec_len(serverip));
	pbm->port = port;

	return 0;
}

int disconnect_server (protobuf_main_t * pbm)
{
	if (pbm && pbm->client)
	{
		protobuf_client_disconnect(pbm->client);
		memset (pbm->hostname, 0, 16 * sizeof (u8));
		pbm->port = 0;
	    return 0;
	}
    return 1;
}

void vlib_cli_output(struct vlib_main_t * vm, char * fmt, ...)
{ clib_warning ("BUG"); }

int main (int argc, char ** argv)
{
	protobuf_main_t * pbm = &protobuf_main;
    unformat_input_t _argv, *input = &_argv;
    u8 * heap;
    mheap_t * h;

    clib_mem_init (0, 128<<20);

    heap = clib_mem_get_per_cpu_heap();
    h = mheap_header (heap);
      
    /* make the main heap thread-safe */
    h->flags |= MHEAP_FLAG_THREAD_SAFE;

    unformat_init_command_line (input, argv);

    u8 * serverIP = 0;
    u32 port = ~0;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "host %s", &serverIP))
        	;
        else if (unformat (input, "port %d", &port))
        	;
        else {
            fformat (stderr, "%s: usage [in <f1> ... in <fn>] [out <fn>]\n");
            exit (1);
        }
    }

    if (serverIP == 0 || port == ~0) {
        fformat (stderr, "Please specify hostname and port\nUsage : %s host <ip4-addr> port <n>\n", argv[0]);
        exit (1);
    }

    protobuf_main.allocator.alloc = &pb_alloc;
    protobuf_main.allocator.free = &pb_free;
    protobuf_main.allocator.allocator_data = NULL;
    protobuf_main.ev_loop = ev_default_loop(0);
    protobuf_main.port = 0;
    protobuf_main.client = NULL;

    clib_time_init (&pbm->clib_time);

    protobuf_api_hookup(&protobuf_main);

    if (connect_to_vpe("vpp_protobuf") < 0) {
        svm_region_exit();
        fformat (stderr, "Couldn't connect to vpe, exiting...\n");
        exit (1);
    }

    protobuf_interface_dump(&protobuf_main);

    while(1)
    {
        protobuf_main.client = protobuf_tcp_connect(protobuf_main.client, (const char*)serverIP, port);
        if (protobuf_main.client != NULL) {
            clib_warning("Connected to client %s:%d", serverIP, port);
        	memcpy(protobuf_main.client->address, protobuf_main.hostname, 16);
            // start processing events while any watcher is active
            ev_run(protobuf_main.ev_loop, 0);
        }

        // if client is not connected or it disconnected
        clib_warning("Retry ...");
        sleep(3);
    }

    protobuf_client_free(protobuf_main.client);

    vl_client_disconnect_from_vlib();
    exit (0);
}
