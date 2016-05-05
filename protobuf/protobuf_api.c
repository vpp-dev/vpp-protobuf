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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

#include "vppprotobuf.h"
#include "pb_format.h"
#include "protobuf_api.h"

/* define message IDs */
#include <protobuf/protobuf_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <protobuf/protobuf_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <protobuf/protobuf_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <protobuf/protobuf_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <protobuf/protobuf_all_api_h.h>
#undef vl_api_version

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

int vl_msg_api_pd_handler (void *mp, int rv)
{
    api_main_t * am = &api_main;
    int (*fp)(void *, int);
    u16 msg_id;

    if (clib_arch_is_little_endian)
        msg_id = clib_net_to_host_u16(*((u16 *)mp));
    else
        msg_id = *((u16 *)mp);

    if (msg_id >= vec_len (am->pd_msg_handlers)
        || am->pd_msg_handlers[msg_id] == 0)
        return rv;

    fp = am->pd_msg_handlers [msg_id];
    rv = (*fp)(mp, rv);
    return rv;
}

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+pbm->msg_id_base);              \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO2(t, body)                                   \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+pbm->msg_id_base);              \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define foreach_protobuf_plugin_api_msg                         \
_(PROTOBUF_CONNECT_SERVER, protobuf_connect_server)				\
_(PROTOBUF_CONNECTION_STATUS, protobuf_connection_status)		\
_(PROTOBUF_DISCONNECT, protobuf_disconnect)

/* Action function shared between message handler and debug CLI */

static clib_error_t * connect_server_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
	protobuf_main_t * pbm = &protobuf_main;
    u8 address_set = 0, is_ipv6 = 0;
    u8 serverIP[16];
    u32 port = ~0;

    /* Parse args required to build the message */
    while (unformat_check_input (input) != ~0)
    {
         if (unformat (input, "%U", unformat_ip4_address, &serverIP))
        	 address_set = 1;

         else if (unformat (input, "%U", unformat_ip6_address, &serverIP))
         {
        	 address_set = 1;
        	 is_ipv6 = 1;
         }

         else if (unformat (input, "port %d", &port))
        	 ;

         else
           break;
    }

    if (address_set == 0 || port == ~0)
    	return clib_error_return (0, "Please specify server address and port to connect to ...");

	int rv = connect_server (pbm, serverIP, port, is_ipv6);
	switch(rv) {
		case 0:
			break;

		case VNET_API_ERROR_UNIMPLEMENTED:
			return clib_error_return (0, "ERROR API unimplemented");
			break;

		default:
			return clib_error_return (0, "Protobuf connect_server returned %d", rv);
	}
	return 0;
}

VLIB_CLI_COMMAND (cli_protobuf_connect_command, static) = {
    .path = "protobuf connect_server",
    .short_help = "protobuf connect_server <ip4-addr|ip6-addr> port <n>",
    .function = connect_server_command_fn,
};

static void vl_api_protobuf_connect_server_t_handler (vl_api_protobuf_connect_server_t * mp)
{
	vl_api_protobuf_connect_server_reply_t * rmp;
	protobuf_main_t * pbm = &protobuf_main;

	int rv = connect_server (pbm, mp->address, ntohs(mp->port), mp->is_ipv6);
	REPLY_MACRO(VL_API_PROTOBUF_CONNECT_SERVER_REPLY);
}

static clib_error_t * connection_status_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
	protobuf_client_t * client = protobuf_main.client;
	if (client != NULL)
		vlib_cli_output (vm, "Client is connected to %s:%d\n", client->hostname, client->port);
	else
		vlib_cli_output (vm, "Client is disconnected\n");

	return 0;
}

VLIB_CLI_COMMAND (cli_protobuf_connection_status_command, static) = {
    .path = "protobuf connection_status",
    .short_help = "protobuf connection_status",
    .function = connection_status_command_fn,
};

static void vl_api_protobuf_connection_status_t_handler (vl_api_protobuf_connection_status_t * mp)
{
	vl_api_protobuf_connection_status_reply_t * rmp;
	protobuf_main_t * pbm = &protobuf_main;

    int rv = 0;
    REPLY_MACRO2(VL_API_PROTOBUF_CONNECTION_STATUS_REPLY,
    ({
    	rmp->is_connected = 0;
    	if (pbm->client != NULL)
    	{
            rmp->is_connected = 1;
            rmp->is_ipv6 = pbm->client->is_ipv6;
        	memcpy (rmp->address, pbm->client->address, (rmp->is_ipv6)?16:4);
            rmp->port = ntohs(pbm->client->port);
    	}
    }));
}

static clib_error_t * disconnection_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
    clib_warning ("Disconnecting ...");

    // send the event to plugin
    ev_async_send (protobuf_main.ev_loop, &protobuf_main.client->ev_disconnect);

    return 0;
}

VLIB_CLI_COMMAND (cli_protobuf_disconnect_command, static) = {
    .path = "protobuf disconnect",
    .short_help = "protobuf disconnect",
    .function = disconnection_command_fn,
};

static void vl_api_protobuf_disconnect_t_handler (vl_api_protobuf_disconnect_t * mp)
{
	vl_api_protobuf_disconnect_reply_t * rmp;
	protobuf_main_t * pbm = &protobuf_main;

    clib_warning ("Disconnecting ...");

    // send the event to plugin
    ev_async_send (protobuf_main.ev_loop, &protobuf_main.client->ev_disconnect);

    int rv = 0;//disconnect_server (pbm);
	REPLY_MACRO(VL_API_PROTOBUF_DISCONNECT_REPLY);
}

/* Set up the API message handling tables */
clib_error_t *
protobuf_plugin_api_hookup (vlib_main_t *vm, protobuf_main_t *pbm)
{
    u8 * name = format (0, "protobuf_%08x%c", api_version, 0);

    /* Ask for a correctly-sized block of API message decode slots */
    pbm->msg_id_base = vl_msg_api_get_msg_ids
        ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + pbm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
    foreach_protobuf_plugin_api_msg;
#undef _

    vec_free(name);

    return 0;
}
