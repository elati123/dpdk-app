#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <stdio.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define PACKET_LEN 64

// Destination and source MAC addresses
static const struct rte_ether_addr dst_mac = { .addr_bytes = {0x08, 0x00, 0x27, 0x53, 0x8b, 0x4f} };
static const struct rte_ether_addr src_mac = { .addr_bytes = {0x08, 0x00, 0x27, 0x65, 0xf4, 0x6a} };

static void send_packets(struct rte_mempool *mbuf_pool, uint16_t portid) {
    struct rte_mbuf *mbufs[BURST_SIZE];
    int pkt_len = PACKET_LEN;
    
    for (int i = 0; i < BURST_SIZE; i++) {
        // Allocate a packet buffer
        mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
        if (mbufs[i] == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to allocate mbuf\n");
        }

        // Set up Ethernet header
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
        rte_ether_addr_copy(&src_mac, &eth_hdr->src_addr);
        rte_ether_addr_copy(&dst_mac, &eth_hdr->dst_addr);
        eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        // Add custom payload (dummy data)
        char *payload = rte_pktmbuf_append(mbufs[i], pkt_len - sizeof(struct rte_ether_hdr));
        if (payload == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to add payload to mbuf\n");
        }
        snprintf(payload, pkt_len - sizeof(struct rte_ether_hdr), "DPDK Packet Generator");

        // Set the total length of the packet
        mbufs[i]->data_len = pkt_len;
        mbufs[i]->pkt_len = pkt_len;
    }

    // Transmit the burst of packets
    const uint16_t nb_tx = rte_eth_tx_burst(portid, 0, mbufs, BURST_SIZE);
    if (nb_tx < BURST_SIZE) {
        for (uint16_t i = nb_tx; i < BURST_SIZE; i++) {
            rte_pktmbuf_free(mbufs[i]);
        }
    }

    printf("Sent %u packets\n", nb_tx);
}

static void print_port_stats(uint16_t port_id) {
    struct rte_eth_stats stats;
    rte_eth_stats_get(port_id, &stats);

    printf("Port %u stats:\n", port_id);
    printf("  RX packets: %lu\n", stats.ipackets);
    printf("  TX packets: %lu\n", stats.opackets);
    printf("  RX errors:  %lu\n", stats.ierrors);
    printf("  TX errors:  %lu\n", stats.oerrors);
    printf("  RX dropped: %lu\n", stats.imissed);
    printf("  RX no mbuf: %lu\n", stats.rx_nombuf);
}


int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    uint16_t portid;
    uint16_t nb_ports;
/*
    // Get the number of available ports
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
    rte_exit(EXIT_FAILURE, "No available ports\n");
*/
    // Initialize DPDK EAL
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_panic("Cannot init EAL\n");
    argc -= ret;
    argv += ret;

    // Create a memory pool for storing packet buffers
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Initialize the port (e.g., port 0)
    portid = 0;
    if (!rte_eth_dev_is_valid_port(portid)) {
        rte_exit(EXIT_FAILURE, "Invalid port\n");
    }

    struct rte_eth_conf port_conf = {0};   
    if (rte_eth_dev_configure(portid, 1, 1, &port_conf) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot configure device\n");
    }

    // Allocate and set up RX and TX queues
    if (rte_eth_rx_queue_setup(portid, 0, 128, rte_eth_dev_socket_id(portid), NULL, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "RX queue setup failed\n");
    }
    if (rte_eth_tx_queue_setup(portid, 0, 128, rte_eth_dev_socket_id(portid), NULL) != 0) {
        rte_exit(EXIT_FAILURE, "TX queue setup failed\n");
    }

    // Start the Ethernet port
    if (rte_eth_dev_start(portid) != 0) {
        rte_exit(EXIT_FAILURE, "Device start failed\n");
    }

    // Generate and send packets
    send_packets(mbuf_pool, portid);

    //port stats
    print_port_stats(portid);

    // Stop and close the port
    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);

    return 0;
}


