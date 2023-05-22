// used with VeriFast, no pragma
#ifndef RTE_TCP_H
#define RTE_TCP_H

#include <stdint.h>

/**
 * TCP Flags
 */
#define RTE_TCP_CWR_FLAG 0x80 /**< Congestion Window Reduced */
#define RTE_TCP_ECE_FLAG 0x40 /**< ECN-Echo */
#define RTE_TCP_URG_FLAG 0x20 /**< Urgent Pointer field significant */
#define RTE_TCP_ACK_FLAG 0x10 /**< Acknowledgment field significant */
#define RTE_TCP_PSH_FLAG 0x08 /**< Push Function */
#define RTE_TCP_RST_FLAG 0x04 /**< Reset the connection */
#define RTE_TCP_SYN_FLAG 0x02 /**< Synchronize sequence numbers */
#define RTE_TCP_FIN_FLAG 0x01 /**< No more data from sender */

struct rte_tcp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t sent_seq;
  uint32_t recv_ack;
  uint8_t data_off;
  uint8_t tcp_flags;
  uint16_t rx_win;
  uint16_t cksum;
  uint16_t tcp_urp;
};

#endif
