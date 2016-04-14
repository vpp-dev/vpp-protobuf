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

#include <vppinfra/error.h>
/* For sockaddr_in */
#include <netinet/in.h>
/* For socket functions */
#include <sys/socket.h>
/* For gethostbyname */
#include <netdb.h>
#include <fcntl.h>
#include "vppprotobuf.h"
#include "tcpclient.h"

static void protobuf_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

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
    strncpy(client->address, hostname, sizeof(client->address));
    client->address[sizeof(client->address)-1] = '\0';
    client->port = port;

    // store pointer to client so we can use it when event occurs
    client->ev_read.data = client;

    // workaround for bogus strict aliasing warning in gcc 4
    struct ev_io *ev_read = &client->ev_read; 
    ev_io_init(ev_read, protobuf_read_cb, fd, EV_READ);
    ev_io_start(protobuf_main.ev_loop, ev_read);
    // TODO: ev_io_init(client->ev_write, protobuf_write_cb, fd, EV_WRITE);

    return client;
}

void protobuf_client_disconnect(protobuf_client_t *client)
{
    if (client == NULL)
        return;

    ev_io_stop(protobuf_main.ev_loop, &client->ev_read);
    close(client->fd);
}

void protobuf_client_free(protobuf_client_t *client)
{
    if (client == NULL)
        return;

    vec_free(client->buf_read);
    free(client);
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

    return rsize;
}

static void protobuf_process_buffer(protobuf_client_t *client, const uint8_t *buf, ssize_t buf_size)
{
    struct ev_loop *loop = protobuf_main.ev_loop;

    VppRequest *req = vpp_request__unpack(&protobuf_allocator, buf_size, buf);
    if (req == NULL) {
        clib_warning("error unpacking incoming GPB request, "
                "closing client connection");
        protobuf_client_disconnect(client);
        return;
    }

    // TODO: do something with the processed request

    vpp_request__free_unpacked(req, &protobuf_allocator);
}

static void protobuf_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
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
                    clib_warning("error reading data from client %s:%d. closing connection", client->address, client->port);
                else
                    clib_warning("client %s:%d disconnected", client->address, client->port);
                protobuf_client_disconnect(client);
                return;
            }

            if (client->remaining_size == 0
                    || client->remaining_size > MAX_GPB_MESSAGE_SIZE) {
                clib_warning("received invalid message size %d from client "
                        "%s:%d. closing connection",
                        client->remaining_size, client->address, client->port);
                protobuf_client_disconnect(client);
                return;
            }
            // resize buffer to fit whole message
            vec_validate(client->buf_read, client->remaining_size);
            // reset buffer length
            _vec_len(client->buf_read) = 0;

            client->state = PBC_STATE_READMSG;

        case PBC_STATE_READMSG:
            rsize = recv(client->fd, client->buf_read, client->remaining_size, 0);
            if (rsize <= 0) {
                if (rsize < 0)
                    clib_warning("error reading data from client %s:%d. "
                            "closing connection", client->address, client->port);
                else
                    clib_warning("client %s:%d disconnected",
                            client->address, client->port);
                protobuf_client_disconnect(client);
                return;
            }

            clib_warning("received data of size %d", rsize);

            // if we didn't read whole message
            if (rsize < client->remaining_size) {
                _vec_len(client->buf_read) += rsize;
                return;
            }

            // got full message, process it
            protobuf_process_buffer(client, client->buf_read, vec_len(client->buf_read));

            // set idle state and let libev call read event again if needed
            client->state = PBC_STATE_IDLE;
            break;
        default:
            clib_warning("client %s:%d unknown state %d. closing connection",
                    client->address, client->port, client->state);
            protobuf_client_disconnect(client);
            break;
    }
}

void protobuf_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
}
