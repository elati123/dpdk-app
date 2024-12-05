#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <openssl/hmac.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define CUSTOM_HEADER_TYPE 0x0833

struct ipv6_srh
{
    uint8_t next_header;  // Next header type
    uint8_t hdr_ext_len;  // Length of SRH in 8-byte units
    uint8_t routing_type; // Routing type (4 for SRv6)
    uint8_t segments_left;
    uint8_t last_entry;
    uint8_t flags;               // Segments yet to be visited
    uint8_t reserved[2];         // Reserved for future use
    struct in6_addr segments[2]; // Array of IPv6 segments max 10 nodes
};

struct hmac_tlv
{
    uint8_t type;           // 1 byte for TLV type
    uint8_t length;         // 1 byte for TLV length
    uint16_t d_flag : 1;    // 1-bit D flag
    uint16_t reserved : 15; // Remaining 15 bits for reserved
    uint32_t hmac_key_id;   // 4 bytes for the HMAC Key ID
    uint64_t hmac_value;    // 8 Octets HMAC value must be multiples of 8 octetx and ma is 32 octets
};

void display_mac_address(uint16_t port_id)
{
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

static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {0};
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;

    // Configure the Ethernet device
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    // Allocate and set up RX queues
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    // Allocate and set up TX queues
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                        rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    // Start the Ethernet port
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    // Enable RX in promiscuous mode for the port
    rte_eth_promiscuous_enable(port);

    return 0;
}

void decrypt_hmac_ip6(struct rte_mbuf *mbuf)
{
    struct ipv6_srh *srh;
    struct hmac_tlv *hmac;
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    srh = (struct ipv6_srh *)(ipv6_hdr + 1); // SRH follows IPv6 header
    hmac = (struct hmac_tlv *)(srh + 1);
}

int main(int argc, char *argv[])
{

    struct rte_mempool *mbuf_pool;
    uint16_t port_id = 0;
    uint16_t tx_port_id = 1;

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
    if (port_init(tx_port_id, mbuf_pool) != 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", tx_port_id);
    }
    else
    {
        display_mac_address(tx_port_id);
    }
    printf("Capturing packets on port %d...\n", port_id);

    for (;;)
    {
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        for (int i = 0; i < nb_rx; i++)
        {
            struct rte_mbuf *mbuf = bufs[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

            switch (rte_be_to_cpu_16(eth_hdr->ether_type))
            {
            case RTE_ETHER_TYPE_IPV4:
                printf("ip4 packet\n");
                break;
            case RTE_ETHER_TYPE_IPV6:
                process_ip6_with_srh(eth_hdr, mbuf, i);
                break;
            default:
                break;
            }
        }
    }
}