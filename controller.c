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

struct ipv6_srh
{
    uint8_t next_header;         // Next header type
    uint8_t hdr_ext_len;         // Length of SRH in 8-byte units
    uint8_t routing_type;        // Routing type (4 for SRv6)
    uint8_t segments_left;       // Segments yet to be visited
    uint8_t reserved[4];         // Reserved for future use
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

void print_ipv6_address(const struct in6_addr *ipv6_addr, const char *label)
{
    char addr_str[INET6_ADDRSTRLEN]; // Buffer for human-readable address

    // Convert the IPv6 binary address to a string
    if (inet_ntop(AF_INET6, ipv6_addr, addr_str, sizeof(addr_str)) != NULL)
    {
        printf("%s: %s\n", label, addr_str);
    }
    else
    {
        perror("inet_ntop");
    }
}

// Initialize a port
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

void process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf, int i)
{
    printf("\nip6 packet is encountered\n");
    struct ipv6_srh *srh;
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    srh = (struct ipv6_srh *)(ipv6_hdr + 1); // SRH follows IPv6 header
    if (ipv6_hdr->proto == 43 && srh->next_header == 61 )
    {
        printf("segment routing detected");
        
        struct hmac_tlv *hmac;
        
        hmac = (struct hmac_tlv *)(srh + 1);

        // Display source and destination MAC addresses
        printf("Packet %d:\n", i + 1);
        printf("  Src MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
               eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
               eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
               eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
        printf("  Dst MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
               eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
               eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
               eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
        printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));

        print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "source");
        print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "destination");

        // Get srh pointer after ipv6 header
        if (ipv6_hdr->proto == IPPROTO_ROUTING)
        {
            printf("The size of srh is %lu\n", sizeof(*srh));
            printf("The size of hmac is %lu\n", sizeof(*hmac));
            printf("The size of hmac is %lu\n", sizeof(eth_hdr));
            // print_ipv6_address(srh->segments, "the only segment in the demo packet");
            printf("the routing type of srh is %d\n", srh->segments_left);
            print_ipv6_address(srh->segments + 1, "asd");
            printf("HMAC type: %u\n", hmac->type);
            printf("HMAC length: %u\n", hmac->length);
            printf("HMAC key ID: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));

            // TODO burayı dinamik olarak bastır çünkü hmac 8 octet (8 byte 64 bit) veya katı olabilir şimdilik i 1 den başıyor ve i-1 yazdırıyor
            for (int i = 1; i < hmac->length / sizeof(uint64_t); i++)
            {
                printf("HMAC value[%d]: %016lx\n", i, hmac->hmac_value);
            }

            fflush(stdout);
        }
    }
}


void process_ip4(struct rte_mbuf *mbuf, uint16_t nb_rx, struct rte_ether_hdr *eth_hdr, int i)
{
    printf("number of the packets received is %d", nb_rx);

    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    // Display source and destination MAC addresses
    printf("Packet %d:\n", i + 1);
    printf("  Src MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
           eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
           eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
           eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
    printf("  Dst MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
           eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
           eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
    // If the packet is IPv4, display source and destination IP addresses

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

    // Free the mbuf after processing
    rte_pktmbuf_free(mbuf);
}

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

    RTE_ETH_FOREACH_DEV(port_id)
    {
        // Packet capture loop
        for (;;)
        {

            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

            if (unlikely(nb_rx == 0))
                continue;

            for (int i = 0; i < nb_rx; i++)
            {
                printf("captured something\n");
                struct rte_mbuf *mbuf = bufs[i];
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

                switch (rte_be_to_cpu_16(eth_hdr->ether_type))
                {
                case RTE_ETHER_TYPE_IPV4:
                    process_ip4(mbuf, nb_rx, eth_hdr, i);
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

    return 0;
}
