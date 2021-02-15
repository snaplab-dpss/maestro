#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>

#define MBUF_CACHE_SIZE 256
#define RSS_HASH_KEY_LENGTH 52
#define MAX_NUM_DEVICES 32 // this is quite arbitrary...

#define RETA_CONF_SIZE (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)
#define MAX_N_CHUNKS 100

RTE_DECLARE_PER_LCORE(void **, chunks_borrowed);
RTE_DECLARE_PER_LCORE(size_t, chunks_borrowed_num);

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES];

struct lcore_conf {
  struct rte_mempool* mbuf_pool;
  uint16_t queue_id;
};

struct lcore_conf lcores_conf[RTE_MAX_LCORE];

void reta_from_file(uint16_t reta[ETH_RSS_RETA_SIZE_512]);
void set_reta(uint16_t device, uint16_t reta[ETH_RSS_RETA_SIZE_512]);
