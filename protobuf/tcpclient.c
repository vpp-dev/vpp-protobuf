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

static void protobuf_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    char buffer[BUFFER_SIZE + 1];
    ssize_t rsize;

    if (EV_ERROR & revents) {
        clib_warning("error during read event");
        return;
    }

    rsize = recv(watcher->fd, buffer, BUFFER_SIZE, 0);

    if (rsize == 0) {
        protobuf_client_t *client = (protobuf_client_t *)(watcher->data);
        ev_io_stop(loop, watcher);
        clib_warning("client %s:%d disconnected", client->address, client->port);
        return;
    }

    buffer[rsize] = 0;
    clib_warning("received message: %s", buffer);
}

void protobuf_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
}

