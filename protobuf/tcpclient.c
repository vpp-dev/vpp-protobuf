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

/* For sockaddr_in */
#include <netinet/in.h>
/* For socket functions */
#include <sys/socket.h>
/* For gethostbyname */
#include <netdb.h>
#include <fcntl.h>
#include <vnet/map/map.h>
#include "vppprotobuf.h"
#include "msghandler.h"
#include "tcpclient.h"

static void protobuf_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void protobuf_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void disconnect_callback(struct ev_loop *loop, struct ev_async *watcher, int revents);

protobuf_client_t *protobuf_tcp_connect(protobuf_client_t *client, const char *hostname, int port)
{
    struct sockaddr_in sin;
    struct hostent *h;
    int fd;

    /* Look up the IP address for the hostname.   Watch out; this isn't
       threadsafe on most platforms. */
    h = gethostbyname(hostname);
    if (!h) {
        clib_warning("Couldn't lookup %s: %s", hostname, hstrerror(h_errno));
        return NULL;
    }
    if (h->h_addrtype != AF_INET) {
        clib_warning("No ipv6 support, sorry.");
        return NULL;
    }

    /* Allocate a new socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        clib_warning("Cannot create socket (%s)", strerror(errno));
        return NULL;
    }

    /* Connect to the remote host. */
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr = *(struct in_addr*)h->h_addr;
    if (connect(fd, (struct sockaddr*) &sin, sizeof(sin))) {
        clib_warning("Cannot connect to host %s:%d (%s)", hostname, port, strerror(errno));
        close(fd);
        return NULL;
    }

    if (client == NULL)
        client = (protobuf_client_t *)clib_mem_alloc(sizeof(protobuf_client_t));
    if (client == NULL) {
        clib_warning("Cannot allocate client object memory");
        close(fd);
        return NULL;
    }

    // non blocking socket
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    client->fd = fd;
    strncpy(client->hostname, hostname, sizeof(client->hostname));
    client->hostname[sizeof(client->hostname)-1] = '\0';
    client->port = port;

    // store pointer to client so we can use it when event occurs
    client->ev_read.data = client;
    client->ev_write.data = client;

    client->sent = 0;
    client->remaining_size = 0;

    // client is idle / waiting for message
    client->state = PBC_STATE_IDLE;

    // workaround for bogus strict aliasing warning in gcc 4
    struct ev_io *ev_w = &client->ev_read;

    ev_io_init(ev_w, protobuf_read_cb, fd, EV_READ);
    ev_io_start(protobuf_main.ev_loop, ev_w);

    ev_w = &client->ev_write;
    ev_io_init(ev_w, protobuf_write_cb, fd, EV_WRITE);

    // prepare disconnect event handler
	struct ev_async *ev_disconnect = &client->ev_disconnect;
    ev_async_init (ev_disconnect, disconnect_callback);
    ev_async_start (protobuf_main.ev_loop, ev_disconnect);

    return client;
}

void protobuf_client_disconnect(protobuf_client_t *client)
{
    if (client == NULL)
        return;

    ev_io_stop(protobuf_main.ev_loop, &client->ev_read);
    ev_io_stop(protobuf_main.ev_loop, &client->ev_write);
    close(client->fd);
    ev_break(protobuf_main.ev_loop, EVBREAK_ONE);
}

void protobuf_client_free(protobuf_client_t *client)
{
    if (client == NULL)
        return;

    vec_free(client->buf_read);
    vec_free(client->buf_write);

    ipv4_destination_t * ipv4_k_dest = 0;
    ipv4_address_t * ipv4_v_hops;
    hash_foreach_mem (ipv4_k_dest, ipv4_v_hops, protobuf_main.ipv4_hops_by_destination_addr_table,
    ({
    	vec_free (ipv4_v_hops);
    }));
    hash_free (protobuf_main.ipv4_hops_by_destination_addr_table);

    ipv6_destination_t * ipv6_k_dest = 0;
    ipv6_address_t * ipv6_v_hops;
    hash_foreach_mem (ipv6_k_dest, ipv6_v_hops, protobuf_main.ipv6_hops_by_destination_addr_table,
    ({
    	vec_free (ipv6_v_hops);
    }));
    hash_free (protobuf_main.ipv6_hops_by_destination_addr_table);

    clib_mem_free(client);
}

static uint32_t protobuf_read_msg_size(protobuf_client_t *client)
{
    ssize_t rsize = 0;
    uint32_t msg_size = 0;

    // read size of incoming message
    rsize = recv(client->fd, &msg_size, sizeof(msg_size), 0);
    // if disconnected or error
    if (rsize <= 0)
        return rsize;

    msg_size = ntohl(msg_size);

    // store expected message size
    client->remaining_size = msg_size;

    clib_warning("DEBUG: expected msg size: %d", msg_size);

    return rsize;
}

static void protobuf_process_buffer(protobuf_client_t *client, const uint8_t *buf, ssize_t buf_size)
{
    protobuf_main_t *pbm = &protobuf_main;
    int rc = 0;

    VppRequest *req = vpp_request__unpack(&pbm->allocator, buf_size, buf);
    if (req == NULL) {
        clib_warning("error unpacking incoming GPB request, closing client connection");
        protobuf_client_disconnect(client);
        return;
    }

    rc = protobuf_handle_request(client, req);
    if (rc < 0) {
        clib_warning("error processing request from %s:%d message id: %d", client->hostname, client->port, req->id);
    }

    vpp_request__free_unpacked(req, &pbm->allocator);
}

static void protobuf_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    protobuf_main_t *pbm = &protobuf_main;
    protobuf_client_t *client = (protobuf_client_t *)(watcher->data);
    ssize_t rsize = 0;

    if (EV_ERROR & revents) {
        clib_warning("error during read event");
        return;
    }

    switch(client->state) {
        case PBC_STATE_IDLE:
            rsize = protobuf_read_msg_size(client);
            if (rsize <= 0) {
                if (rsize < 0)
                    clib_warning("error reading data from client %s:%d. closing connection", client->hostname, client->port);
                else
                    clib_warning("client %s:%d disconnected", client->hostname, client->port);
                protobuf_client_disconnect(client);
                return;
            }

            if (client->remaining_size == 0
                    || client->remaining_size > MAX_GPB_MESSAGE_SIZE) {
                clib_warning("received invalid message size %d from client "
                        "%s:%d. closing connection",
                        client->remaining_size, client->hostname, client->port);
                protobuf_client_disconnect(client);
                return;
            }
            // resize buffer to fit whole message
            vec_validate(client->buf_read, client->remaining_size);
            // reset buffer length
            _vec_len(client->buf_read) = 0;

            client->state = PBC_STATE_READMSG;

        case PBC_STATE_READMSG:
            rsize = recv(client->fd, client->buf_read + vec_len(client->buf_read),
                    client->remaining_size, 0);
            if (rsize <= 0) {
                if (rsize < 0)
                    clib_warning("error reading data from client %s:%d. "
                            "closing connection", client->hostname, client->port);
                else
                    clib_warning("client %s:%d disconnected",
                            client->hostname, client->port);
                protobuf_client_disconnect(client);
                return;
            }

            clib_warning("received data of size %d", rsize);
            _vec_len(client->buf_read) += rsize;

            // if we didn't read whole message
            if (rsize < client->remaining_size) {
                client->remaining_size -= rsize;
                return;
            }

            // stop processing read events for this client until
            // message is processed and response is sent
            ev_io_stop(pbm->ev_loop, &client->ev_read);

            client->remaining_size = 0;

            // got full message, process it
            protobuf_process_buffer(client, client->buf_read, vec_len(client->buf_read));

            // set idle state and let libev call read event again if needed
            client->state = PBC_STATE_IDLE;
            break;
        default:
            clib_warning("client %s:%d unknown state %d. closing connection",
                    client->hostname, client->port, client->state);
            protobuf_client_disconnect(client);
            break;
    }
}

static void protobuf_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    protobuf_main_t *pbm = &protobuf_main;
    protobuf_client_t *client = (protobuf_client_t *)(watcher->data);
    ssize_t sent = 0;

    if (EV_ERROR & revents) {
        clib_warning("error during write event");
        return;
    }

    sent = send(client->fd, client->buf_write + client->sent,
            vec_len(client->buf_write) - client->sent, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EPIPE)
            clib_warning("client %s:%d disconnected before response was sent", client->address, client->port);
        else
            clib_warning("error sending response to %s:%d (%s)", client->hostname, client->port, strerror(errno));
        protobuf_client_disconnect(client);
        return;
    }

    // if we didn't send everything
    if (sent + client->sent < vec_len(client->buf_write)) {
        client->sent += sent;
        return; // wait for next write event
    }

    // reset write buffer
    _vec_len(client->buf_write) = 0;
    client->sent = 0;

    clib_warning("sent whole message");

    // stop write event watcher until we have something to write
    ev_io_stop(pbm->ev_loop, &client->ev_write);

    // start processing read events again
    ev_io_start(pbm->ev_loop, &client->ev_read);
}

static void disconnect_callback(struct ev_loop *loop, struct ev_async *watcher, int revents)
{
    protobuf_main_t *pbmain = &protobuf_main;

    // stop event watcher as we've got response already
    ev_async_stop (pbmain->ev_loop, &pbmain->client->ev_disconnect);
    disconnect_server (pbmain);
    clib_warning ("Disconnected ...");
}
