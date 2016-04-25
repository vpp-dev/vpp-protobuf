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
#include "msghandler.h"

#define VERSION_STRING "TestVersion 0.000001"

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
static void protobuf_send_response(protobuf_client_t *client, VppResponse *resp);

// request context structure used in rpc calls to vpp main thread
typedef struct {
    struct ev_async *ev_response;
    void *context;
} protobuf_vpp_request_context_t;

// get version function called in vpp main thread
static void vpp_get_version_rpc_callback(void *args)
{
    /* NOTE: this is just example vpe_api_get_version is not available from plugin for now */

    protobuf_main_t *pbmain = &protobuf_main;
    ASSERT(os_get_cpu_number() == 0);
    char * vpe_api_get_version (void);
    protobuf_vpp_request_context_t *ctx = args;
    protobuf_vpp_event_data_t *ev_data = (protobuf_vpp_event_data_t *)ctx->ev_response->data;

    // FIXME: undefined reference to vpe_api_get_version() 
    // (needs the call in vlib for it to be accessible)
    //ev_data->context = vpe_api_get_version();

    // FIXME: send back version
    ev_data->context = VERSION_STRING;

    // send the event to plugin
    ev_async_send (pbmain->ev_loop, ctx->ev_response);

}

static void vpp_get_version_response_callback(struct ev_loop *loop, struct ev_async *watcher, int revents)
{
    protobuf_main_t *pbmain = &protobuf_main;
    VppVersionResp msg = VPP_VERSION_RESP__INIT;
    // get event data from watcher context
    protobuf_vpp_event_data_t *ev_data = (protobuf_vpp_event_data_t *)watcher->data;
    // get client from event data context
    protobuf_client_t *client = ev_data->client;
    // get prepared response from client data
    VppResponse *resp = &client->resp;

    // get version from event data context
    msg.version = (char *)ev_data->context;

    // reset event context (no free as it is static string in this case)
    ev_data->context = NULL;

    // stop event watcher as we've got response already
    ev_async_stop (pbmain->ev_loop, &client->ev_vpp);

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

    // send response (payload always gets freed after response is serialized)
    protobuf_send_response(client, resp);
}

/* get version request called when gpb get version request is received */
static void protobuf_req_get_version(protobuf_client_t *client, VppResponse *resp)
{
    protobuf_main_t *pbmain = &protobuf_main;
    struct ev_async *ev_vpp = &client->ev_vpp;
    // prepare response event handler
    ev_async_init (ev_vpp, vpp_get_version_response_callback);
    ev_async_start (pbmain->ev_loop, ev_vpp);

    // TODO: locking
    protobuf_vpp_request_context_t ctx;
    ctx.ev_response = &client->ev_vpp;
    ctx.context = NULL;    // we will get version response here

    // call vpp main thread to get vpp version & wait for response
    vl_api_rpc_call_main_thread (vpp_get_version_rpc_callback, (u8 *)&ctx, sizeof(ctx));
}

// handle received request
int protobuf_handle_request(protobuf_client_t *client, VppRequest *req)
{
    protobuf_main_t *pbmain = &protobuf_main;

    // init response
    vpp_response__init(&client->resp);
    client->resp.id = req->id;

    // handle different types of messages
    switch(req->type) {
        case REQUEST_TYPE__GET_VERSION:
            clib_warning("received get version request from %s:%d", client->address, client->port);
            // call get version request, response will be sent in async response from vpp main thread
            protobuf_req_get_version(client, &client->resp);
            break;
        default:
            clib_warning("unknown request type %d from %s:%d", req->type, client->address, client->port);
            client->resp.retcode = -1;   // FIXME
            // immediately send error response
            protobuf_send_response(client, &client->resp);
            break;
    }

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

