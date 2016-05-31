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

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <api/vpe.api.h>
#undef vl_api_version

#include "msghandler.h"

void vl_client_add_api_signatures (vl_api_memclnt_create_t *mp)
{
    /*
     * Send the main API signature in slot 0. This bit of code must
     * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
     */
    mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}

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

/*
 * Generate boilerplate reply handlers, which
 * dig the return value out of the xxx_reply_t API message,
 * stick it into vam->retval, and set vam->result_ready
 *
 * Could also do this by pointing N message decode slots at
 * a single function, but that could break in subtle ways.
 */
#define foreach_standard_reply_retval_handler   \
_(control_ping_reply)                           \
_(ip_add_del_route_reply)

#define _(n)                                    \
    static void vl_api_##n##_t_handler          \
    (vl_api_##n##_t * mp)                       \
    {                                           \
        protobuf_main_t * pbm = &protobuf_main; \
        i32 retval = ntohl(mp->retval);         \
        if (pbm->async_mode) {                  \
        	pbm->async_errors += (retval < 0);  \
        } else {                                \
        	pbm->retval = retval;               \
        	pbm->result_ready = 1;              \
        }                                       \
    }
foreach_standard_reply_retval_handler;
#undef _

// handler to avoid "msg_handler_internal:364: no handler for msg id 13" warning
static void vl_api_sw_interface_set_flags_t_handler (vl_api_sw_interface_set_flags_t * mp)
{
}

// process dump interfaces response
static void vl_api_sw_interface_details_t_handler (vl_api_sw_interface_details_t * mp)
{
    protobuf_main_t *pbm = &protobuf_main;
    u8 * s = format (0, "%s%c", mp->interface_name, 0);
    hash_set_mem (pbm->sw_if_index_by_interface_name, s, ntohl(mp->sw_if_index));
}

// process show version response
static void vl_api_show_version_reply_t_handler (vl_api_show_version_reply_t * mp)
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

/*
 * Table of message reply handlers
*/

#define foreach_vpe_api_reply_msg                       \
_(SW_INTERFACE_DETAILS, sw_interface_details)           \
_(SW_INTERFACE_SET_FLAGS, sw_interface_set_flags)       \
_(CONTROL_PING_REPLY, control_ping_reply)               \
_(SHOW_VERSION_REPLY, show_version_reply)               \
_(IP_ADD_DEL_ROUTE_REPLY, ip_add_del_route_reply)

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

    pbm->ipv4_hops_by_destination_addr_table = hash_create_mem (0, sizeof (ipv4_destination_t), sizeof(u8*));
    pbm->ipv6_hops_by_destination_addr_table = hash_create_mem (0, sizeof (ipv6_destination_t), sizeof(u8*));
}

// call vpp dump interfaces to create map of interface name to sw_if_index and wait for response
int protobuf_interface_dump (protobuf_main_t *pbm)
{
    vl_api_sw_interface_dump_t *mp;
    f64 timeout;

    /* recreate the interface name hash table */
    pbm->sw_if_index_by_interface_name = hash_create_string (0, sizeof(uword));

    /* Get list of ethernets */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "Ether", sizeof(mp->name_filter)-1);
    S;

    /* and local / loopback interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "lo", sizeof(mp->name_filter)-1);
    S;

    /* and vxlan tunnel interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "vxlan", sizeof(mp->name_filter)-1);
    S;

    /* and host (af_packet) interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "host", sizeof(mp->name_filter)-1);
    S;

    /* and l2tpv3 tunnel interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "l2tpv3_tunnel", sizeof(mp->name_filter)-1);
    S;

    /* and GRE tunnel interfaces */
    M(SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "gre", sizeof(mp->name_filter)-1);
    S;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t * mp;
        M(CONTROL_PING, control_ping);
        S;
    }
    W;
    /* NOTREACHED */
    return 0;
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

static void dbg_destination_routes(protobuf_main_t * pbm, ipv4_destination_t * ipv4_destination, ipv6_destination_t * ipv6_destination)
{
    uword * p = 0;
    char ipv6_buffer[INET6_ADDRSTRLEN];
    char ipv4_buffer[INET_ADDRSTRLEN];

    if (ipv6_destination != NULL) {
    	clib_warning("Searching for destination %s/%d", inet_ntop(AF_INET6, &ipv6_destination->address, ipv6_buffer,sizeof(ipv6_buffer)), ipv6_destination->prefix);
    	p = hash_get_mem (pbm->ipv6_hops_by_destination_addr_table, ipv6_destination);
    }
    else {
    	clib_warning("Searching for ipv4 destination %s/%d", inet_ntop(AF_INET, &ipv4_destination->address, ipv4_buffer,sizeof(ipv4_buffer)), ipv4_destination->prefix);
    	p = hash_get_mem (pbm->ipv4_hops_by_destination_addr_table, ipv4_destination);
    }
    if (p == 0)
    	clib_warning("empty hop addrs vector ...");
    else {
    	clib_warning("# hop addrs : %d", vec_len(p[0]));
    	int i;
    	ipv4_address_t * ipv4_hop;
    	ipv6_address_t * ipv6_hop;
    	for (i=0; i<vec_len(p[0]); i++) {
    		if (ipv6_destination != NULL) {
    			ipv6_hop = (ipv6_address_t*) vec_elt_at_index((ipv6_address_t*)p[0], i);
    			clib_warning("ipv6 : %s",inet_ntop(AF_INET6, ipv6_hop, ipv6_buffer,sizeof(ipv6_buffer)));
    		}
    		else {
    			ipv4_hop = (ipv4_address_t*) vec_elt_at_index((ipv4_address_t*)p[0], i);
    			clib_warning("ipv4 : %s", inet_ntop(AF_INET, ipv4_hop, ipv4_buffer,sizeof(ipv4_buffer)));
    		}
    	}
    	clib_warning("...........");
    }
}

static void dbg_allhops(protobuf_main_t * pbm)
{
	char ipv6_buffer[INET6_ADDRSTRLEN];
	char ipv4_buffer[INET_ADDRSTRLEN];

	clib_warning("Current hops ...");
	ipv4_destination_t * ipv4_k_dest = 0;
	ipv4_address_t * ipv4_v_hops;
	clib_warning("ipv4 dest ...");
	hash_foreach_mem (ipv4_k_dest, ipv4_v_hops, pbm->ipv4_hops_by_destination_addr_table,
			({
		int i;
		ipv4_address_t * hop;
		for (i=0; i<vec_len(ipv4_v_hops); i++) {
			hop = (ipv4_address_t*) vec_elt_at_index(ipv4_v_hops, i);
			clib_warning("%s", inet_ntop(AF_INET, hop, ipv4_buffer, sizeof(ipv4_buffer)));
		}
	}));
	ipv6_destination_t * ipv6_k_dest = 0;
	ipv6_address_t * ipv6_v_hops;
	clib_warning("ipv6 dest ...");
	hash_foreach_mem (ipv6_k_dest, ipv6_v_hops, pbm->ipv6_hops_by_destination_addr_table,
			({
		int i;
		ipv6_address_t * hop;
		for (i=0; i<vec_len(ipv6_v_hops); i++) {
			hop = (ipv6_address_t*) vec_elt_at_index(ipv6_v_hops, i);
			clib_warning("%s",inet_ntop(AF_INET6, hop, ipv6_buffer,sizeof(ipv6_buffer)));
		}
	}));
	clib_warning("................");
}

// call ip_add_del_route vpp api call and wait for response
static int ip_add_del_route (VppRoute * req_route, VppRoute__Operation operation)
{
	if (req_route->iproute != NULL) {
		protobuf_main_t * pbm = &protobuf_main;
		VppIpRoute * req_iproute = req_route->iproute;

		vl_api_ip_add_del_route_t *mp;
		f64 timeout;

		uword * p = 0;
		ipv4_destination_t ipv4_destination;
		ipv6_destination_t ipv6_destination;
		if (req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV6) {
			memcpy(ipv6_destination.address.as_u8, req_iproute->address.data, req_iproute->address.len);
			ipv6_destination.prefix = req_iproute->prefix;
		}
		else {
			memcpy(ipv4_destination.address.as_u8, req_iproute->address.data, req_iproute->address.len);
			ipv4_destination.prefix = req_iproute->prefix;
		}

		// TODO : remove debug print
		dbg_destination_routes(pbm, (req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV6)?0:&ipv4_destination,
				(req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV4)?0:&ipv6_destination);

		// check if route already exists and delete it
		if (operation != VPP_ROUTE__OPERATION__ADD) {
			if (req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV6)
				p = hash_get_mem (pbm->ipv6_hops_by_destination_addr_table, &ipv6_destination);
			else
				p = hash_get_mem (pbm->ipv4_hops_by_destination_addr_table, &ipv4_destination);
			if (p == 0) {
				char ipv6_buffer[INET6_ADDRSTRLEN];
				char ipv4_buffer[INET_ADDRSTRLEN];
				const char *dest;
				u32 prefix;

				if (req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV6) {
					dest = inet_ntop(AF_INET6, &ipv6_destination.address, ipv6_buffer,sizeof(ipv6_buffer));
					prefix = ipv6_destination.prefix;
				}
				else {
					dest = inet_ntop(AF_INET, &ipv4_destination.address, ipv4_buffer,sizeof(ipv4_buffer));
					prefix = ipv4_destination.prefix;
				}

				if (operation == VPP_ROUTE__OPERATION__REMOVE)
					clib_warning("Delete route : route for destination %s/%d doesn't exist", dest, prefix);
				else
					clib_warning("Update route : route for destination %s/%d doesn't exist, use ADD operation", dest, prefix);
				return 0;
			}

			// prepare message to delete existing route
			M(IP_ADD_DEL_ROUTE, ip_add_del_route);

			mp->is_add = 0;
			if (req_route->has_vrfid)
				mp->vrf_id = ntohl (req_route->vrfid);
			mp->is_ipv6 = (req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV6)?1:0;
			mp->classify_table_index = ~0;
			memcpy(mp->dst_address, req_iproute->address.data, req_iproute->address.len);
			mp->dst_address_length = req_iproute->prefix;

			S;

			if (req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV6) {
				ipv6_address_t * hops_addr_ipv6 = (ipv6_address_t*)p[0];
				vec_free(hops_addr_ipv6);
			}
			else {
				ipv4_address_t * hops_addr_ipv4 = (ipv4_address_t*)p[0];
				vec_free(hops_addr_ipv4);
			}
			if (req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV6)
				hash_unset_mem (pbm->ipv6_hops_by_destination_addr_table, &ipv6_destination);
			else
				hash_unset_mem (pbm->ipv4_hops_by_destination_addr_table, &ipv4_destination);
		}
		if (operation != VPP_ROUTE__OPERATION__REMOVE) {
			// prepare message to add new route
			M(IP_ADD_DEL_ROUTE, ip_add_del_route);

			mp->is_add = 1;
			if (req_route->has_vrfid)
				mp->vrf_id = ntohl (req_route->vrfid);
			mp->is_ipv6 = (req_route->proto == VPP_ROUTE__ROUTE_PROTOCOL__IPV6)?1:0;
			mp->classify_table_index = ~0;
			//mp->is_drop = 0;
			//mp->is_local = 0;
			//mp->is_classify = 0;
			//mp->is_multipath = 0;
			//mp->lookup_in_vrf = 0;
			//mp->create_vrf_if_needed = 0;
			memcpy(mp->dst_address, req_iproute->address.data, req_iproute->address.len);
			mp->dst_address_length = req_iproute->prefix;

			if (req_route->iproute->n_nexthops>0) {
				mp->resolve_if_needed = 1;
				mp->resolve_attempts = ntohl (3);

				u32	ipv4_hops = 0;
				u32	ipv6_hops = 0;

				uint32_t	hop;
				for (hop=0; hop<req_route->iproute->n_nexthops; hop++)
				{
					VppNextHop * req_hop = req_route->iproute->nexthops[hop];
					if (req_hop->proto == VPP_NEXT_HOP__NEXT_HOP_PROTOCOL__IPV6)
						ipv6_hops++;
					else
						ipv4_hops++;
				}

				ipv4_address_t * hops_addr_ipv4 = vec_new(ipv4_address_t, ipv4_hops);
				ipv6_address_t * hops_addr_ipv6 = vec_new(ipv6_address_t, ipv6_hops);

				for (hop=0; hop<req_route->iproute->n_nexthops; hop++)
				{
					VppNextHop * req_hop = req_route->iproute->nexthops[hop];
					if (req_hop->interface_name != NULL) {
						uword * p_sw_if_index = hash_get_mem (pbm->sw_if_index_by_interface_name, (u8 *)req_hop->interface_name);
						if (p_sw_if_index)
							mp->next_hop_sw_if_index = ntohl (p_sw_if_index[0]);
						else { // Couldn't find specified interface name
							clib_warning("Couldn't find specified interface name");
							continue;
						}
					}
					if (req_hop->has_ipaddress) {
						memcpy(mp->next_hop_address, req_hop->ipaddress.data, req_hop->ipaddress.len);
						if (mp->is_ipv6)
							memcpy(&hops_addr_ipv6[hop], req_hop->ipaddress.data, req_hop->ipaddress.len);
						else
							memcpy(&hops_addr_ipv4[hop], req_hop->ipaddress.data, req_hop->ipaddress.len);
					}
					if (req_hop->has_weight)
						mp->next_hop_weight = ntohl (req_hop->weight);
					mp->not_last = (hop<req_route->iproute->n_nexthops-1)?1:0;

					S;
				}

				hash_set_mem (pbm->ipv4_hops_by_destination_addr_table, &ipv4_destination, hops_addr_ipv4);
				hash_set_mem (pbm->ipv6_hops_by_destination_addr_table, &ipv6_destination, hops_addr_ipv6);

			}

			// TODO : remove debug print
			dbg_allhops(pbm);

			/* Use a control ping for synchronization */
			{
				vl_api_control_ping_t * mp;
				M(CONTROL_PING, control_ping);
				S;
			}
		}

		W;
	}
	/* NOTREACHED */
	return 0;
}

// get version request called when gpb get version request is received
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

// cfg_route request called when gpb cfg_routes request is received
static void protobuf_req_cfg_routes(protobuf_client_t *client, VppResponse *resp, VppRequest *req)
{
    //read payload from request
    VppRoutesCfgReq * req_routes = vpp_routes_cfg_req__unpack(0, req->payload.len, req->payload.data);

    client->resp.type = RESPONSE_TYPE__SIMPLE;
    client->resp.retcode = 0;

    uint32_t 	i;
    for (i=0; i<req_routes->n_routes; i++)
    {
    	client->resp.retcode = ip_add_del_route (req_routes->routes[i], req_routes->routes[i]->op);
        if (client->resp.retcode  != 0) {
            if (client->resp.retcode == -99) {
        		clib_warning("Connection to vpe lost ... ");
				protobuf_main.reconnect_to_vpe = 1;
				ev_break(protobuf_main.ev_loop, EVBREAK_ONE);
	            break;
            }
            else {
        	    uword * p = hash_get (protobuf_main.error_string_by_error_number, -client->resp.retcode);
        	    if (p)
        	    	clib_warning("Error : %s", p[0]);
        	    else
        	    	clib_warning("Error : %d", client->resp.retcode);
            }
        }
    }

    vpp_routes_cfg_req__free_unpacked(req_routes, 0);
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

    if (vec_len(client->buf_write) > 0) {
        // start write event watcher to write response to client
        ev_io_start(protobuf_main.ev_loop, &client->ev_write);
    }
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
        case REQUEST_TYPE__CFG_ROUTES:
            clib_warning("received cfg_routes from %s:%d", client->hostname, client->port);
            // call cfg routes request, response will be sent in async response from vpp main thread
            protobuf_req_cfg_routes(client, &client->resp, req);
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
