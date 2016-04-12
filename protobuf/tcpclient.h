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
#ifndef __VPPPROTOBUF_TCPCLIENT_H__
#define __VPPPROTOBUF_TCPCLIENT_H__

#include <ev.h>

#define BUFFER_SIZE 1024

typedef struct {
    int fd;
    struct ev_io ev_read;
    struct ev_io ev_write;

    char address[128];
    int port;
} protobuf_client_t;

/**
 * @brief Connect TCP socket to host on port
 *
 * @param client existing allocated client structure or NULL to allocate new one
 * @param hostname hostname to connect to
 * @param port tcp port to connect to
 * @return pointer to allocated protobuf client structure or NULL indicating error
 */
protobuf_client_t *protobuf_tcp_connect(protobuf_client_t *client, const char *hostname, int port);

#endif

