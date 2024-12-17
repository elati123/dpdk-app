#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

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
    uint8_t hmac_value[32]; // 8 Octets HMAC value must be multiples of 8 octetx and ma is 32 octets
};
struct pot_tlv
{
    uint8_t type;               // Type field (1 byte)
    uint8_t length;             // Length field (1 byte)
    uint8_t reserved;           // Reserved field (1 byte)
    uint8_t nonce_length;       // Nonce Length field (1 byte)
    uint32_t key_set_id;        // Key Set ID (4 bytes)
    uint8_t nonce[16];          // Nonce (variable length)
    uint8_t encrypted_hmac[32]; // Encrypted HMAC (variable length)
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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Context creation failed\n");
    }
    // Use counter mode
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
    {
        printf("Decryption initialization failed\n");
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        printf("Decryption update failed\n");
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        printf("Decryption finalization failed\n");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int decrypt_pvf(uint8_t *k_pot_in, uint8_t *nonce, uint8_t pvf_out[32])
{
    // k_pot_in is a 2d array of strings holding statically allocated keys for the nodes. In this proof of concept there is only one middle node and an egress node
    // so the shape is [2][key-length]
    uint8_t plaintext[128];
    int cipher_len = 32;
    printf("\n----------Decrypting----------\n");
    int dec_len = decrypt(pvf_out, cipher_len, k_pot_in, nonce, plaintext);
    printf("Dec len %d\n", dec_len);
    printf("original text is:\n");
    for (int j = 0; j < 32; j++)
    {
        printf("%02x", pvf_out[j]);
    }
    printf("\n");
    memcpy(pvf_out, plaintext, 32);
    printf("Decrypted text is : \n");
    BIO_dump_fp(stdout, (const char *)pvf_out, dec_len);
}

void process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf, int i)
{
    printf("\n###########################################################################\n");
    printf("\nip6 packet is encountered\n");
    struct ipv6_srh *srh;
    struct pot_tlv *pot;
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    srh = (struct ipv6_srh *)(ipv6_hdr + 1); // SRH follows IPv6 header
    pot = (struct pot_tlv *)(srh + 1);

    printf("the proto nums are %d and %d\n", ipv6_hdr->proto, srh->next_header);
    if (srh->next_header == 61 && ipv6_hdr->proto == 43)
    {
        printf("segment routing detected\n");

        struct hmac_tlv *hmac;
        struct pot_tlv *pot;
        hmac = (struct hmac_tlv *)(srh + 1);
        pot = (struct pot_tlv *)(hmac + 1);
        //The key of this node (middle)
        uint8_t k_pot_in[32] =  "eerreerreerreerreerreerreerreer";


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
            printf("The size of pot is %lu\n", sizeof(*pot));

            printf("HMAC type: %u\n", hmac->type);
            printf("HMAC length: %u\n", hmac->length);
            printf("HMAC key ID: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));
            printf("HMAC size: %ld\n", sizeof(hmac->hmac_value));

            // TODO burayı dinamik olarak bastır çünkü hmac 8 octet (8 byte 64 bit) veya katı olabilir şimdilik i 1 den başıyor ve i-1 yazdırıyor
            printf("HMAC value: \n");
            for (int i = 0; i < 32; i++)
            {
                printf("%02x", hmac->hmac_value[i]);
            }
            printf("\nPVF value before decrypting: \n");
            for (int i = 0; i < 32; i++)
            {
                printf("%02x", pot->encrypted_hmac[i]);
            }
            //decrypyt one time with the key of node
            // first declare the value to store decrypted pvf
            uint8_t pvf_out[32];
            memcpy(pvf_out,pot->encrypted_hmac,32);
            decrypt_pvf(k_pot_in,pot->nonce,pvf_out);

            //update the pot header pvf field
            memcpy(pot->encrypted_hmac,pvf_out,32);

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
                struct rte_mbuf *mbuf = bufs[i];
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

                switch (rte_be_to_cpu_16(eth_hdr->ether_type))
                {
                case RTE_ETHER_TYPE_IPV4:
                    process_ip4(mbuf, nb_rx, eth_hdr, i);
                    break;
                case RTE_ETHER_TYPE_IPV6:
                    process_ip6_with_srh(eth_hdr, mbuf, i);
                    //send the packet to eggress node
                    if(rte_eth_tx_burst(tx_port_id,0,&mbuf,1)== 0)
                    {
                        printf("Error sending packet");
                        rte_pktmbuf_free(mbuf);
                    }
                    else{
                        printf("IP6 packet successfully sent");
                    }
                    printf("\n###########################################################################\n");
                    break;
                default:
                    break;
                }
            }
        }
    }

    return 0;
}
