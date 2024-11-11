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

struct custom_hdr {
    char str[5];
    uint16_t num2;
};


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

void add_custom_header(struct rte_mbuf *pkt) {

    // Copy the ethernet header since it will be removed to add the custom header
    struct rte_ether_hdr *tmp_eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (tmp_eth_hdr == NULL) {
        printf("Failed to prepend space for temporary Ethernet header.\n");
        return;
    }
     printf("Inspecting the temporary header is valid???????: %02X:%02X:%02X:%02X:%02X:%02X\n",
               tmp_eth_hdr->src_addr.addr_bytes[0], tmp_eth_hdr->src_addr.addr_bytes[1],
               tmp_eth_hdr->src_addr.addr_bytes[2], tmp_eth_hdr->src_addr.addr_bytes[3],
               tmp_eth_hdr->src_addr.addr_bytes[4], tmp_eth_hdr->src_addr.addr_bytes[5]);

    // need to save this in fresh structs the reason is explained after prepending the custom header
    struct rte_ether_addr tmp_src = tmp_eth_hdr->src_addr;
    struct rte_ether_addr tmp_dst= tmp_eth_hdr->dst_addr;


    // Remove the old ethernet header
    
    rte_pktmbuf_adj(pkt,(uint16_t)sizeof(struct rte_ether_hdr));

    // Reserve space for the custom header at the beginning of the packet
    struct custom_hdr *cust_hdr = (struct custom_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct custom_hdr));
    // !!!!!! Starting from this line the pointer location returned by mtod above (tmp_eth_hdr) points to the custom header address that is why we saved the addresses in seperate structs!!!!!!
    if (cust_hdr == NULL) {
        printf("Failed to prepend space for custom header.\n");
        return;
    }

    // Populate your custom header fields
    //snprintf(cust_hdr->str1,7,"HELLO WORLD");
    strncpy(cust_hdr->str,"melih",sizeof(cust_hdr->str));
    cust_hdr->num2 = rte_cpu_to_be_32(0xDEADBEEF); // Example value in big-endian format

    // Prepend the Ethernet header as well, if needed
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct rte_ether_hdr));
    if (eth_hdr == NULL) {
        printf("Failed to prepend space for Ethernet header.\n");
        return;
    }

    // Set Ethernet header fields
    
    
    eth_hdr->ether_type = rte_cpu_to_be_16(CUSTOM_HEADER_TYPE); // Custom EtherType for custom protocol
    eth_hdr->src_addr = tmp_src;
    eth_hdr->dst_addr = tmp_dst;

    printf("Inspecting the changed header is network byte order: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
               eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
               eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
    //rte_ether_addr_copy(&tmp_eth_hdr->src_addr, &eth_hdr->src_addr);
    //rte_ether_addr_copy(&tmp_eth_hdr->dst_addr, &eth_hdr->dst_addr);

    
    printf("Custom header added to packet.\n");
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
            if(ipv4_hdr->dst_addr  == rte_cpu_to_be_32(RTE_IPV4(10, 0, 2, 44))){

            
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
                if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
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


                add_custom_header(mbuf);

                //change the mac address and the ip address to make basically a repeater
                struct rte_ether_hdr *new_eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *); // header is changed
                struct rte_ether_addr tmp_mac = new_eth_hdr->dst_addr;
                new_eth_hdr->dst_addr = new_eth_hdr->src_addr;
                new_eth_hdr->src_addr = tmp_mac;

                // change the ip
                struct custom_hdr *cst_hdr = (struct custom_hdr *)(eth_hdr + 1);
                struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(cst_hdr + 1);
                rte_be32_t tmp_ip = ipv4_hdr->dst_addr;
                ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
                ipv4_hdr->src_addr = tmp_ip;



                if (rte_eth_tx_burst(port_id, 0, &mbuf, 1) == 0) {
                printf("Error sending packet\n");
                rte_pktmbuf_free(mbuf);
                } else {
                    printf("Packet sent\n");
                }



                // Free the mbuf after processing
                rte_pktmbuf_free(mbuf);
        
        }
    }
    }

    }
    

    return 0;
}