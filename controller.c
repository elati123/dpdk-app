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

void display_mac_address(uint16_t port_id) {
    struct rte_ether_addr mac_addr;
    
    // Retrieve the MAC address of the specified port
    rte_eth_macaddr_get(port_id, &mac_addr);

    // Display the MAC address
    printf("MAC address of port %u: %02X:%02X:%02X:%02X:%02X:%02X\n",
           port_id,
           mac_addr.addr_bytes[0],
           mac_addr.addr_bytes[1],
           mac_addr.addr_bytes[2],
           mac_addr.addr_bytes[3],
           mac_addr.addr_bytes[4],
           mac_addr.addr_bytes[5]);
}

// Initialize a port
static int port_init(uint16_t port,struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = {0};
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;

    // Configure the Ethernet device
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) return retval;

    // Allocate and set up RX queues
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
            rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
    }

    // Allocate and set up TX queues
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
            rte_eth_dev_socket_id(port), NULL);
        if (retval < 0) return retval;
    }

    // Start the Ethernet port
    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    // Enable RX in promiscuous mode for the port
    rte_eth_promiscuous_enable(port);

    return 0;
}


int main(int argc, char *argv[]) {
    
    struct rte_mempool *mbuf_pool;
    uint16_t port_id = 0;
    
    // Initialize the Environment Abstraction Layer (EAL)
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    // Check that there is at least one port available
    if (rte_eth_dev_count_avail() == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    }

    // Create a memory pool to hold the mbufs
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(),
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Initialize the port
    if (port_init(port_id,mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", port_id);
    }
    else{
        display_mac_address(port_id);
    }
    printf("Capturing packets on port %d...\n", port_id);

    RTE_ETH_FOREACH_DEV(port_id){
        // Packet capture loop
    for (;;) {
        
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        
        if (unlikely(nb_rx==0))
            continue;
        
        
        for (int i = 0; i < nb_rx; i++) {
            struct rte_mbuf *mbuf = bufs[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
           
            printf("number of the packets received is %d",nb_rx);
            // Display source and destination MAC addresses
            printf("Packet %d:\n", i + 1);
            printf("  Src MAC: %02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"\n",
                eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
                eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
                eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
            printf("  Dst MAC: %02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"\n",
                eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
                eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
                eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
                printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
                // If the packet is IPv4, display source and destination IP addresses
            if (eth_hdr->ether_type == rte_cpu_to_be_16(CUSTOM_HEADER_TYPE)) {
                struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                printf("  Src IP: %d.%d.%d.%d\n",
                    (ipv4_hdr->src_addr & 0xff),
                    (ipv4_hdr->src_addr >> 8) & 0xff,
                    (ipv4_hdr->src_addr >> 16) & 0xff,
                    (ipv4_hdr->src_addr >> 24) & 0xff);
                printf(
                    "  Dst IP: %d.%d.%d.%d\n",
                    (ipv4_hdr->dst_addr & 0xff),
                    (ipv4_hdr->dst_addr >> 8) & 0xff,
                    (ipv4_hdr->dst_addr >> 16) & 0xff,
                    (ipv4_hdr->dst_addr >> 24) & 0xff);
                }

            // Free the mbuf after processing
            rte_pktmbuf_free(mbuf);
        
        }
    }

    }
    

    return 0;
}
