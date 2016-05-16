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

/* for htonl */
#include <arpa/inet.h>
/* for send */
#include <sys/socket.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <api/vpe_msg_enum.h>

#define vl_typedefs             /* define message structures */
#include <api/vpe_all_api_h.h> 
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <api/vpe_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <api/vpe_all_api_h.h>
#undef vl_printfun
#include "msghandler.h"

static void protobuf_send_response(protobuf_client_t *client, VppResponse *resp);

/* M: construct, but don't yet send a message */
#define M(T,t)                                  \
do {                                            \
    pbm->result_ready = 0;                      \
    mp = vl_msg_api_alloc(sizeof(*mp));         \
    memset (mp, 0, sizeof (*mp));               \
    mp->_vl_msg_id = ntohs (VL_API_##T);        \
    mp->client_index = pbm->my_client_index;    \
} while(0);

#define M2(T,t,n)                               \
do {                                            \
    pbm->result_ready = 0;                      \
    mp = vl_msg_api_alloc(sizeof(*mp)+(n));     \
    memset (mp, 0, sizeof (*mp));               \
    mp->_vl_msg_id = ntohs (VL_API_##T);        \
    mp->client_index = pbm->my_client_index;    \
} while(0);


/* S: send a message */
#define S (vl_msg_api_send_shmem (pbm->vl_input_queue, (u8 *)&mp))

/* W: wait for results, with timeout */
#define W                                       \
do {                                            \
    timeout = protobuf_time_now (pbm) + 1.0;    \
                                                \
    while (protobuf_time_now (pbm) < timeout) { \
        if (pbm->result_ready == 1) {           \
            return (pbm->retval);               \
        }                                       \
    }                                           \
    return -99;                                 \
} while(0);

// process show version response
static void vl_api_show_version_reply_t_handler
(vl_api_show_version_reply_t * mp)
{
    protobuf_main_t * pbm = &protobuf_main;
    i32 retval = ntohl(mp->retval);

    if (retval >= 0) {
        int len = strnlen((char *)mp->version, 128);
        vec_validate(pbm->vpp_version, len + 1);
        memcpy(pbm->vpp_version, mp->version, len);
        pbm->vpp_version[len] = '\0';
    }
    pbm->retval = retval;
    pbm->result_ready = 1;
}

// call show version vpp api call and wait for response
static int api_show_version ()
{
    protobuf_main_t * pbm = &protobuf_main;
    vl_api_show_version_t *mp;
    f64 timeout;

    M(SHOW_VERSION, show_version);

    S; W;
    /* NOTREACHED */
    return 0;
}

/* get version request called when gpb get version request is received */
static void protobuf_req_get_version(protobuf_client_t *client, VppResponse *resp)
{
    protobuf_main_t *pbm = &protobuf_main;
    VppVersionResp msg = VPP_VERSION_RESP__INIT;
    int rc = 0;

    // get vpp version
    rc = api_show_version();
    if (rc != 0) {
        resp->type = RESPONSE_TYPE__SIMPLE;
        resp->retcode = rc;
        return;
    }

    // set response type
    resp->type = RESPONSE_TYPE__VPP_VERSION;
    msg.version = (char *)pbm->vpp_version;

    // prepare payload
    u8 *payload = NULL;
    // calculate payload size
    size_t packed_size = vpp_version_resp__get_packed_size(&msg);

    // allocate payload
    vec_validate(payload, packed_size - 1);

    // pack message into payload buffer
    vpp_version_resp__pack(&msg, payload);
    // make sure the payload has correct size 
    // (if we reuse it and we already had larger one before)
    _vec_len(payload) = packed_size;

    // set payload to the response
    resp->payload.len = vec_len(payload);
    resp->payload.data = payload;
    resp->has_payload = 1;

    // return code
    resp->retcode = 0;
}

// handle received request
int protobuf_handle_request(protobuf_client_t *client, VppRequest *req)
{
    // init response
    vpp_response__init(&client->resp);
    client->resp.id = req->id;

    // handle different types of messages
    switch(req->type) {
        case REQUEST_TYPE__GET_VERSION:
            clib_warning("received get version request from %s:%d", client->hostname, client->port);
            // call get version request, response will be sent in async response from vpp main thread
            protobuf_req_get_version(client, &client->resp);
            break;
        default:
            clib_warning("unknown request type %d from %s:%d", req->type, client->hostname, client->port);
            client->resp.type = RESPONSE_TYPE__SIMPLE;
            client->resp.retcode = -1;   // FIXME: add error
            break;
    }
    // send response (payload always gets freed after response is serialized)
    protobuf_send_response(client, &client->resp);

    return 0;
}

// pack response to output buffer and start write watcher if needed
static void protobuf_send_response(protobuf_client_t *client, VppResponse *resp)
{
    // get size of buffer after it is packed
    size_t packed_size = vpp_response__get_packed_size(&client->resp);

    // prepare buffer for the uint32 size + packed message
    vec_validate(client->buf_write, packed_size + 4 - 1);
    _vec_len(client->buf_write) = packed_size + 4;

    // write size to first 4 bytes
    *((uint32_t *)client->buf_write) = htonl(packed_size);
    // write packed message to remaining place in buffer
    vpp_response__pack(&client->resp, client->buf_write + 4);

    // free payload buffer if any
    if (client->resp.has_payload)
        vec_free(client->resp.payload.data);

    clib_warning("prepared response");

    if (vec_len(client->buf_write) > 0) {
        // start write event watcher to write response to client
        ev_io_start(protobuf_main.ev_loop, &client->ev_write);
    }
}

/* 
 * Table of message reply handlers
*/

#define foreach_vpe_api_reply_msg                               \
_(SHOW_VERSION_REPLY, show_version_reply)                               

void protobuf_api_hookup(protobuf_main_t *pbm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_vpe_api_reply_msg;
#undef _

    vl_msg_api_set_first_available_msg_id (VL_MSG_FIRST_AVAILABLE);
}

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <api/vpe.api.h>
#undef vl_api_version

void vl_client_add_api_signatures (vl_api_memclnt_create_t *mp)
{
    /*
     * Send the main API signature in slot 0. This bit of code must
     * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
     */
    mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}
