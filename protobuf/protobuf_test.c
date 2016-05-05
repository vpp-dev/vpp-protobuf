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
/*
 *------------------------------------------------------------------
 * protobuf_test.c - test protobuf plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>
#include <vat/json_format.h>
#include "pb_format.h"

/* Declare message IDs */
#include <protobuf/protobuf_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <protobuf/protobuf.api.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <protobuf/protobuf.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <protobuf/protobuf.api.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <protobuf/protobuf.api.h>
#undef vl_api_version

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} protobuf_test_main_t;

protobuf_test_main_t protobuf_test_main;

static void vl_api_protobuf_connection_status_reply_t_handler
(vl_api_protobuf_connection_status_reply_t * mp)
{
    vat_main_t * vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    if (mp->is_connected)
        fformat (vam->ofp, "Client is connected to %U:%d\n",
        		(mp->is_ipv6)?format_ip6_address:format_ip4_address, mp->address, ntohs(mp->port));
    else
        fformat (vam->ofp, "Client is disconnected\n");

    vam->retval = retval;
    vam->result_ready = 1;
}

#define foreach_standard_reply_retval_handler   \
_(protobuf_connect_server_reply)                \
_(protobuf_disconnect_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = protobuf_test_main.vat_main; \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_protobuf_plugin_api_reply_msg                           \
_(PROTOBUF_CONNECT_SERVER_REPLY, protobuf_connect_server_reply)	        \
_(PROTOBUF_CONNECTION_STATUS_REPLY, protobuf_connection_status_reply)   \
_(PROTOBUF_DISCONNECT_REPLY, protobuf_disconnect_reply)

/* M: construct, but don't yet send a message */

#define M(T,t)                                                  \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp));                         \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + pbm->msg_id_base);     \
    mp->client_index = vam->my_client_index;                    \
} while(0);

#define M2(T,t,n)                                               \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp)+(n));                     \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + pbm->msg_id_base);     \
    mp->client_index = vam->my_client_index;                    \
} while(0);

/* S: send a message */
#define S (vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp))

/* W: wait for results, with timeout */
#define W                                       \
do {                                            \
    timeout = vat_time_now (vam) + 1.0;         \
                                                \
    while (vat_time_now (vam) < timeout) {      \
        if (vam->result_ready == 1) {           \
            return (vam->retval);               \
        }                                       \
    }                                           \
    return -99;                                 \
} while(0);

static int api_protobuf_connect_server (vat_main_t * vam)
{
	protobuf_test_main_t * pbm = &protobuf_test_main;
    unformat_input_t * input = vam->input;
    f64 timeout;
    vl_api_protobuf_connect_server_t * mp;

    u8 address_set = 0, is_ipv6 = 0;
    u8 serverIP[16];
    u16 port = ~0;

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

    if (address_set == 0 || port == (u16)~0)
    {
    	errmsg ("Please specify server address and port to connect to ...\n");
        return -99;
    }

    /* Construct the API message */
    M(PROTOBUF_CONNECT_SERVER, protobuf_connect_server);
    mp->is_ipv6 = is_ipv6;
    memcpy (mp->address, serverIP, (is_ipv6)?16:4);
    mp->port = ntohs(port);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_protobuf_connection_status (vat_main_t * vam)
{
	protobuf_test_main_t * pbm = &protobuf_test_main;
    f64 timeout;
    vl_api_protobuf_connection_status_t * mp;

    /* Construct the API message */
    M(PROTOBUF_CONNECTION_STATUS, protobuf_connection_status);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_protobuf_disconnect (vat_main_t * vam)
{
	protobuf_test_main_t * pbm = &protobuf_test_main;
    f64 timeout;
    vl_api_protobuf_disconnect_t * mp;

    /* Construct the API message */
    M(PROTOBUF_DISCONNECT, protobuf_disconnect);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_protobuf_plugin_api_msg \
_(protobuf_connect_server, " <ipv4/ipv6 address> port <number>") \
_(protobuf_connection_status, "")                                \
_(protobuf_disconnect, "")

void vat_api_hookup (vat_main_t *vam)
{
	protobuf_test_main_t * pbm = &protobuf_test_main;
    /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + pbm->msg_id_base),    \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
	foreach_protobuf_plugin_api_reply_msg;
#undef _

    /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
	foreach_protobuf_plugin_api_msg;
#undef _

    /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
	foreach_protobuf_plugin_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
	protobuf_test_main_t * pbm = &protobuf_test_main;
	u8 * name;

	pbm->vat_main = vam;

	name = format (0, "protobuf_%08x%c", api_version, 0);
	pbm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

	if (pbm->msg_id_base != (u16) ~0)
		vat_api_hookup (vam);

	vec_free(name);

	return 0;
}
