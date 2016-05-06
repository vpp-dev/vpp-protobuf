#include <api/vpe_msg_enum.h>
#define vl_typedefs             /* define message structures */
#include <api/vpe_all_api_h.h> 
#undef vl_typedefs

#define vl_endianfun             /* define message structures */
#include <api/vpe_all_api_h.h> 
#undef vl_endianfun

#include "vppprotobuf.h"
#include "vppapi.h"

static void *
protobuf_rx_thread_fn (void *arg)
{
    unix_shared_memory_queue_t *q;
    protobuf_main_t *pbm = &protobuf_main;

    q = pbm->vl_input_queue;

    /* So we can make the rx thread terminate cleanly */
    if (setjmp(pbm->rx_thread_jmpbuf) == 0) {
        pbm->rx_thread_jmpbuf_valid = 1;
        while (1) {
            vl_msg_api_queue_handler (q);
        }
    }
    pthread_exit(0);
}

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <api/vpe.api.h>
#undef vl_api_version

static void protobuf_vl_client_add_api_signatures (vl_api_memclnt_create_t *mp) 
{
    /* 
     * Send the main API signature in slot 0. This bit of code must
     * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
     */
    mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}

static void vl_api_memclnt_create_reply_t_handler (
    vl_api_memclnt_create_reply_t *mp)
{
    protobuf_main_t *pbm = &protobuf_main;
    int rv;

    pbm->my_client_index = mp->index;
    pbm->my_registration = (vl_api_registration_t *)(uword)
        mp->handle;

    rv = ntohl(mp->response);

    if (rv < 0)
        clib_warning ("WARNING: API mismatch detected");
}

static int protobuf_vl_client_connect (char *name, int ctx_quota, int input_queue_size)
{
    protobuf_main_t *pbm = &protobuf_main;
    svm_region_t *svm;
    vl_api_memclnt_create_t *mp;
    vl_api_memclnt_create_reply_t *rp;
    unix_shared_memory_queue_t *vl_input_queue;
    vl_shmem_hdr_t *shmem_hdr;
    int rv=0;
    void *oldheap;
    api_main_t *am = &api_main;

    if (pbm->my_registration) {
        clib_warning ("client %s already connected...", name);
        return -1;
    }

    if (am->vlib_rp == 0) {
        clib_warning ("am->vlib_rp NULL");
        return -1;
    }

    // use shared memory prepared in vpp process
    svm = am->vlib_rp;
    shmem_hdr = am->shmem_hdr;

    if (shmem_hdr == 0 || shmem_hdr->vl_input_queue == 0) {
        clib_warning ("shmem_hdr / input queue NULL");
        return -1;
    }

    pthread_mutex_lock (&svm->mutex);
    oldheap = svm_push_data_heap(svm);
    // get input queue
    vl_input_queue = 
        unix_shared_memory_queue_init (input_queue_size, sizeof(uword), 
                                       getpid(), 0);
    pthread_mutex_unlock(&svm->mutex);
    svm_pop_heap (oldheap);

    // reset our index and registration
    pbm->my_client_index = ~0;
    pbm->my_registration = 0;
    // store input queue
    pbm->vl_input_queue = vl_input_queue;

    // send memclnt_create request
    mp = vl_msg_api_alloc(sizeof(vl_api_memclnt_create_t));
    memset(mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs(VL_API_MEMCLNT_CREATE);
    mp->ctx_quota = ctx_quota;
    mp->input_queue = (uword)vl_input_queue;
    strncpy ((char *) mp->name, name, sizeof(mp->name)-1);

    // add vpp api version
    protobuf_vl_client_add_api_signatures(mp);

    // send to main input queue
    vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *)&mp);

    while (1) {
        int qstatus;
        struct timespec ts, tsrem;
        int i;

        /* Wait up to 10 seconds */
        for (i = 0; i < 1000; i++) {
            qstatus = unix_shared_memory_queue_sub (vl_input_queue, (u8 *)&rp, 
                                                    1 /* nowait */);
            if (qstatus == 0)
                goto read_one_msg;
            ts.tv_sec = 0;
            ts.tv_nsec = 10000*1000;  /* 10 ms */
            while (nanosleep(&ts, &tsrem) < 0)
                ts = tsrem;
        }
        /* Timeout... */
        clib_warning ("memclnt_create_reply timeout");
        return -1;

    read_one_msg:
        if (ntohs(rp->_vl_msg_id) != VL_API_MEMCLNT_CREATE_REPLY) {
            clib_warning ("unexpected reply: id %d", ntohs(rp->_vl_msg_id));
            continue;
        }
        rv = clib_net_to_host_u32(rp->response);

        vl_msg_api_handler((void *)rp);
        break;
    }
    return (rv);
}

static void vl_api_memclnt_delete_reply_t_handler (
    vl_api_memclnt_delete_reply_t *mp)
{
    void *oldheap;
    api_main_t *am = &api_main;
    protobuf_main_t *pbm = &protobuf_main;

    pthread_mutex_lock (&am->vlib_rp->mutex);
    oldheap = svm_push_data_heap(am->vlib_rp);
    unix_shared_memory_queue_free (pbm->vl_input_queue);
    pthread_mutex_unlock (&am->vlib_rp->mutex);
    svm_pop_heap (oldheap);

    pbm->my_client_index = ~0;
    pbm->my_registration = 0;
    pbm->vl_input_queue = 0;
}

static void protobuf_vl_client_disconnect (void)
{
    vl_api_memclnt_delete_t *mp;
    vl_api_memclnt_delete_reply_t *rp;
    unix_shared_memory_queue_t *vl_input_queue;
    vl_shmem_hdr_t *shmem_hdr;
    time_t begin;
    api_main_t *am = &api_main;
    protobuf_main_t *pbm = &protobuf_main;
    
    ASSERT(am->vlib_rp);
    shmem_hdr = am->shmem_hdr;
    ASSERT(shmem_hdr && shmem_hdr->vl_input_queue);

    vl_input_queue = pbm->vl_input_queue;

    mp = vl_msg_api_alloc(sizeof(vl_api_memclnt_delete_t));
    memset(mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs(VL_API_MEMCLNT_DELETE);
    mp->index = pbm->my_client_index;
    mp->handle = (uword) pbm->my_registration;

    vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *)&mp);

    /* 
     * Have to be careful here, in case the client is disconnecting
     * because e.g. the vlib process died, or is unresponsive.
     */
    
    begin = time (0);
    while (1) {
        time_t now;

        now = time (0);

        if (now >= (begin + 2)) {
            clib_warning ("peer unresponsive, give up");
            pbm->my_client_index = ~0;
            pbm->my_registration = 0;
            break;
        }
        if (unix_shared_memory_queue_sub (vl_input_queue, (u8 *)&rp, 1) < 0)
            continue;
        
        /* drain the queue */
        if (ntohs(rp->_vl_msg_id) != VL_API_MEMCLNT_DELETE_REPLY) {
            vl_msg_api_handler ((void *)rp);
            continue;
        }
        vl_msg_api_handler((void *)rp);
        break;
    }
}

#define foreach_api_client_msg                  \
_(MEMCLNT_CREATE_REPLY, memclnt_create_reply)   \
_(MEMCLNT_DELETE_REPLY, memclnt_delete_reply)

static int protobuf_vl_client_api_map (char *region_name)
{
    int rv;

    if ((rv = vl_map_shmem (region_name, 0 /* is_vlib */)) < 0) {
        return rv;
    }

#define _(N,n)                                                          \
    vl_msg_api_set_handlers(VL_API_##N, 0 /* name */,                   \
                           vl_api_##n##_t_handler,                      \
                           0/* cleanup */, 0/* endian */, 0/* print */, \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_api_client_msg;
#undef _
    return 0;
}

int connect_to_vpe(char *name)
{
    protobuf_main_t * pbm = &protobuf_main;
    api_main_t * am = &api_main;
    int rv = 0;

    /*
     * Bail out now if we're not running as root
     */
    if (geteuid() != 0)
        return (-1);

    if ((rv = protobuf_vl_client_api_map("/vpe-api"))) {
        clib_warning ("protobuf_vl_client_api map rv %d", rv);
        return rv;
    }

    if (protobuf_vl_client_connect(name, 0, 32) < 0) {
        vl_client_api_unmap();
        return (-1);
    }

    /* Start the rx queue thread */
    rv = pthread_create(&pbm->rx_thread_handle, NULL, protobuf_rx_thread_fn, 0);
    if (rv) {
        clib_warning("pthread_create returned %d", rv);
        vl_client_api_unmap();
        return (-1);
    }

    pbm->connected_to_vlib = 1;
    return 0;
}

int disconnect_from_vpe(void)
{
    api_main_t *am = &api_main;
    protobuf_main_t *pbm = &protobuf_main;

    if (pbm->rx_thread_jmpbuf_valid)  {
        vl_api_rx_thread_exit_t *ep;
        uword junk;
        ep = vl_msg_api_alloc (sizeof (*ep));
        ep->_vl_msg_id = ntohs(VL_API_RX_THREAD_EXIT);
        vl_msg_api_send_shmem(am->vl_input_queue, (u8 *)&ep);
        pthread_join(pbm->rx_thread_handle, (void  **)&junk);
    }
    if (pbm->connected_to_vlib) {
        protobuf_vl_client_disconnect();
        vl_client_api_unmap();
    }
    pbm->connected_to_vlib = 0;
    pbm->rx_thread_handle = 0;
    pbm->rx_thread_jmpbuf_valid = 0;

    return (0);
}

