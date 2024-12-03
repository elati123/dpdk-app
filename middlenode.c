#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define CUSTOM_HEADER_TYPE 0x0833

int main(int argc, char *argv[])
{

    struct rte_mempool *mbuf_pool;
    uint16_t port_id = 0;

    // Initialize the Environment Abstraction Layer (EAL)
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    // Check that there is at least one port available
    if (rte_eth_dev_count_avail() == 0)
    {
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    }

    // Create a memory pool to hold the mbufs
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(),
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Initialize the port
    if (port_init(port_id, mbuf_pool) != 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port_id);
    }
    else
    {
        display_mac_address(port_id);
    }
    printf("Capturing packets on port %d...\n", port_id);
}