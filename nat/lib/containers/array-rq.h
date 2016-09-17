#ifndef _ARRAY_RQ_H_INCLUDED_
#define _ARRAY_RQ_H_INCLUDED_

#include <stdint.h>
#include "../ignore.h"
#include "../static-component-params.h"

#define MAX_RX_QUEUE_PER_LCORE 16

struct lcore_rx_queue {
  uint8_t port_id;
  uint8_t queue_id;
}
#ifdef _NO_VERIFAST_
  __rte_cache_aligned;
#else//_NO_VERIFAST_
;
#endif//_NO_VERIFAST_

#define ARRAY_RQ_EL_TYPE struct lcore_rx_queue
#define ARRAY_RQ_CAPACITY MAX_RX_QUEUE_PER_LCORE
#define ARRAY_RQ_EL_INIT lcore_rx_queue_init
#define ARRAY_RQ_EL_TRACE_BREAKDOWN {                                   \
    klee_trace_ret_ptr_field(offsetof(struct lcore_rx_queue, port_id),  \
                             sizeof(uint8_t), "port_id");               \
    klee_trace_ret_ptr_field(offsetof(struct lcore_rx_queue, queue_id), \
                             sizeof(uint8_t), "queue_id");              \
  }
#define ARRAY_RQ_EL_TRACE_EP_BREAKDOWN(ep) {                            \
    klee_trace_extra_ptr_field(ep, offsetof(struct lcore_rx_queue, port_id), \
                               sizeof(uint8_t), "port_id");             \
    klee_trace_extra_ptr_field(ep, offsetof(struct lcore_rx_queue, queue_id), \
                               sizeof(uint8_t), "queue_id");            \
  }

#ifdef KLEE_VERIFICATION
struct ArrayRq
{
  char dummy;
};
#else
struct ArrayRq
{
  ARRAY_RQ_EL_TYPE data[ARRAY_RQ_CAPACITY];
};
#endif//KLEE_VERIFICATION

/*@
  inductive rx_queuei = rx_queuei(int,int);
  predicate rx_queuep(rx_queuei rq, struct lcore_rx_queue *lrq) =
            struct_lcore_rx_queue_padding(lrq) &*&
            lrq->port_id |-> ?pi &*&
            lrq->queue_id |-> ?qi &*&
            rq == rx_queuei(pi,qi);
  predicate some_rx_queuep(struct lcore_rx_queue *lrq) = rx_queuep(_, lrq);
  @*/

/*@
  predicate arrp_rq(list<rx_queuei> data, struct ArrayRq *arr);
  predicate arrp_rq_acc(list<rx_queuei> data, struct ArrayRq *arr, int idx);

  fixpoint ARRAY_RQ_EL_TYPE *arrp_the_missing_cell_rq(struct ArrayRq *arr,
                                                      int idx)  {
    return (ARRAY_RQ_EL_TYPE*)(arr->data)+idx;
  }

  lemma void construct_rq_element(ARRAY_RQ_EL_TYPE *p);
  requires p->port_id |-> ?pid &*&
           0 <= pid &*& pid <= RTE_MAX_ETHPORTS &*&
           p->queue_id |-> _ &*&
           struct_lcore_rx_queue_padding(p);
  ensures rx_queuep(_, p);

  @*/

// In-place initialization
void array_rq_init(struct ArrayRq *arr_out);
/*@ requires chars((void*)(arr_out),
                   ARRAY_RQ_CAPACITY*sizeof(ARRAY_RQ_EL_TYPE), _) &*&
             struct_ArrayRq_padding(arr_out); @*/
//@ ensures arrp_rq(_, arr_out);

#endif//_ARRAY_RQ_H_INCLUDED_
