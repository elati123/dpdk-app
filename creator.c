// Melih
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include <stdalign.h>
#include <stdlib.h>
#include <getopt.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf_dyn.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define CUSTOM_HEADER_TYPE 0x0833
#define SID_NO 2        // Total 3 dpdk runnning nodes. 2 of them are sid1 and sid0(egress)
#define NONCE_LENGTH 16 // AES uses 16 bytes of iv
#define EXTRA_SPACE 128

#define HMAC_MAX_LENGTH 32 // Truncate HMAC to 32 bytes if needed

static int operation_bypass_bit = 0;

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

/////////////////////////////////////////////////////////////
// Functions for packet timestamping
static int hwts_dynfield_offset = -1;

static inline rte_mbuf_timestamp_t *
hwts_field(struct rte_mbuf *mbuf)
{
    return RTE_MBUF_DYNFIELD(mbuf,
                             hwts_dynfield_offset, rte_mbuf_timestamp_t *);
}

typedef uint64_t tsc_t;
static int tsc_dynfield_offset = -1;

static inline tsc_t *
tsc_field(struct rte_mbuf *mbuf)
{
    return RTE_MBUF_DYNFIELD(mbuf, tsc_dynfield_offset, tsc_t *);
}

static struct
{
    uint64_t total_cycles;
    uint64_t total_queue_cycles;
    uint64_t total_pkts;
} latency_numbers;

static uint16_t
add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
               struct rte_mbuf **pkts, uint16_t nb_pkts,
               uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
    unsigned i;
    uint64_t now = rte_rdtsc();

    for (i = 0; i < nb_pkts; i++)
        *tsc_field(pkts[i]) = now;
    return nb_pkts;
}

static uint16_t
calc_latency(uint16_t port, uint16_t qidx __rte_unused,
             struct rte_mbuf **pkts, uint16_t nb_pkts, void *_ __rte_unused)
{
    uint64_t cycles = 0;
    uint64_t queue_ticks = 0;
    uint64_t now = rte_rdtsc();
    uint64_t ticks;
    unsigned i;

    printf("TSC frequency: %" PRIu64 " Hz\n", rte_get_tsc_hz());

    for (i = 0; i < nb_pkts; i++)
    {
        cycles += now - *tsc_field(pkts[i]);
    }

    latency_numbers.total_cycles += cycles;

    latency_numbers.total_pkts += nb_pkts;

    printf("Latency = %" PRIu64 " cycles\n",
           latency_numbers.total_cycles / latency_numbers.total_pkts);

    printf("number of packets: %" PRIu64 " Hz\n", latency_numbers.total_pkts);

    double latency_us = (double)latency_numbers.total_cycles / rte_get_tsc_hz() * 1e6; // Convert to microseconds

    printf("Latency: %.3f µs\n", latency_us);

    latency_numbers.total_cycles = 0;
    latency_numbers.total_queue_cycles = 0;
    latency_numbers.total_pkts = 0;

    return nb_pkts;
}

//////////////////////////////////////////////////////////////

// Initialize a port
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {0};
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));

        return retval;
    }
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

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

    /* RX and TX callbacks are added to the ports. 8< */

    /* >8 End of RX and TX callbacks. */

    return 0;
}

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

void add_custom_header6(struct rte_mbuf *pkt)
{

    /*
        SORUN ICIN 2 YAKLASIM: YA BUTUN EKSTRA  HEADERLARI SONA EKLE
        YADA TUM PACKETI APEENDLEYE APPENDLEYE YENIDEN INSAA ET AMA BUNUN ICIN BOMBOS BIR MBUF OLUSTURMAK LAZIM

    */
    // Definitions
    struct ipv6_srh *srh_hdr;
    struct hmac_tlv *hmac_hdr;
    struct pot_tlv *pot_hdr;
    struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
    uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

    printf("Initial available tailroom: %u\n", rte_pktmbuf_tailroom(pkt));
    printf("Initial packet length: %u\n", rte_pktmbuf_pkt_len(pkt));
    // Assuming ip6 packets the size of ethernet header + ip6 header is 54 bytes
    size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;
    printf("Payload size: %lu\n", payload_size);
    uint8_t *tmp_payload = (uint8_t *)malloc(payload_size);
    if (tmp_payload == NULL)
    {
        printf("malloc failed\n");
    }
    // save the payload which will be deleted and added later
    memcpy(tmp_payload, payload, payload_size);

    // Remove the payload
    rte_pktmbuf_trim(pkt, payload_size);
    printf("Available tailroom after trim operations: %u\n", rte_pktmbuf_tailroom(pkt));

    // Add the custom headers in order and finally add the payload
    srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
    hmac_hdr = (struct hmac_tlv *)rte_pktmbuf_append(pkt, sizeof(struct hmac_tlv));
    pot_hdr = (struct pot_tlv *)rte_pktmbuf_append(pkt, sizeof(struct pot_tlv));
    payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
    printf("Packet length after appends: %u\n", rte_pktmbuf_pkt_len(pkt));
    // Populate the fields

    // Reinsert the payload
    memcpy(payload, tmp_payload, payload_size);

    pot_hdr->type = 1;    // made it up since it is tbd
    pot_hdr->length = 48; // 32 b PVF + 16 b nonce
    pot_hdr->reserved = 0;
    pot_hdr->nonce_length = 16;
    pot_hdr->key_set_id = rte_cpu_to_be_32(1234);
    // Initialize the nonce and PVF values (32 bytes of 0x01)
    memset(pot_hdr->nonce, 0, sizeof(pot_hdr->nonce));
    memset(pot_hdr->encrypted_hmac, 0, sizeof(pot_hdr->encrypted_hmac));

    hmac_hdr->type = 5;                             // Type field (fixed to 5 for HMAC TLV)
    hmac_hdr->length = 16;                          // Length of HMAC value in bytes
    hmac_hdr->d_flag = 0;                           // Destination Address verification enabled
    hmac_hdr->reserved = 0;                         // Reserved bits set to zero
    hmac_hdr->hmac_key_id = rte_cpu_to_be_32(1234); // Example HMAC Key ID

    // Populate HMAC value (32 bytes of 0x01)
    memset(hmac_hdr->hmac_value, 0, sizeof(hmac_hdr->hmac_value));

    // 61 Any host internal protocol
    srh_hdr->next_header = 61; // No Next Header in this example
    srh_hdr->hdr_ext_len = 2;  // Length of SRH in 8-byte units, excluding the first 8 bytes
    srh_hdr->routing_type = 4; // Routing type for SRH
    srh_hdr->last_entry = 0;
    srh_hdr->flags = 0;
    srh_hdr->segments_left = 1;      // 1 segment left to visit (can be adjusted)
    memset(srh_hdr->reserved, 0, 2); // Set reserved bytes to zero

    struct in6_addr segments[] = {
        {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}, // Segment 1
        {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}  // Segment 2
    };

    // Copy the segments to the SRH
    memcpy(srh_hdr->segments, segments, sizeof(segments));

    ipv6_hdr->proto = 43;

    printf("Size of POT header: %lu\n", sizeof(struct pot_tlv));
    printf("Size of HMAC header: %lu\n", sizeof(struct hmac_tlv));
    printf("Size of SRH header: %lu\n", sizeof(struct ipv6_srh));

    printf("Custom header added to ip6 packet in the ingress node\n");
}

int calculate_hmac(uint8_t *src_addr,               // Source IPv6 address (16 bytes)
                   const struct ipv6_srh *srh,      // Pointer to the IPv6 Segment Routing Header (SRH)
                   const struct hmac_tlv *hmac_tlv, // Pointer to the HMAC TLV
                   uint8_t *key,                    // Pre-shared key
                   size_t key_len,                  // Length of the pre-shared key
                   uint8_t *hmac_out)               // Output buffer for the HMAC (32 bytes)
{
    // Input text buffer for HMAC computation
    size_t segment_list_len = sizeof(srh->segments);

    size_t input_len = 16 + 1 + 1 + 2 + 4 + segment_list_len; // IPv6 Source + Last Entry + Flags + Length + Key ID + Segment List

    uint8_t input[input_len];

    // Fill the input buffer
    size_t offset = 0;
    memcpy(input + offset, src_addr, 16); // IPv6 Source Address
    offset += 16;

    input[offset++] = srh->last_entry; // Last Entry
    input[offset++] = srh->flags;      // Flags (D-bit + Reserved)

    input[offset++] = 0; // Placeholder for Length (2 bytes, can be zero for this step)
    input[offset++] = 0;

    memcpy(input + offset, &hmac_tlv->hmac_key_id, sizeof(hmac_tlv->hmac_key_id)); // HMAC Key ID
    offset += sizeof(hmac_tlv->hmac_key_id);

    memcpy(input + offset, srh->segments, segment_list_len); // Segment List
    offset += segment_list_len;

    // Perform HMAC computation using OpenSSL
    unsigned int hmac_len;
    uint8_t *digest = HMAC(EVP_sha256(), key, key_len, input, input_len, NULL, &hmac_len);

    if (!digest)
    {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "HMAC computation failed\n");
        return -1;
    }

    // Truncate or pad the HMAC to 32 bytes
    if (hmac_len > HMAC_MAX_LENGTH)
    {
        memcpy(hmac_out, digest, HMAC_MAX_LENGTH);
    }
    else
    {
        memcpy(hmac_out, digest, hmac_len);
        memset(hmac_out + hmac_len, 0, HMAC_MAX_LENGTH - hmac_len); // Pad with zeros
    }

    return 0; // Success
}

// Calculates the PVF using the output of calulcate_hmac function with key k_hmac_ie

int generate_nonce(uint8_t nonce[NONCE_LENGTH])
{
    if (RAND_bytes(nonce, NONCE_LENGTH) != 1)
    {
        printf("Error: Failed to generate random nonce.\n");
        return 1;
    }
    printf("Generated Nonce: ");
    for (int i = 0; i < NONCE_LENGTH; i++)
    {
        printf("%02x", nonce[i]);
    }
    printf("\n");
    return 0;
}
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Context creation failed\n");
    }
    // Use counter mode
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
    {
        printf("Encryption initialization failed\n");
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        printf("Encryption update failed\n");
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        printf("Encryption finalization failed\n");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
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

void encrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t hmac_out[32])
{
    // k_pot_in is a 2d array of strings holding statically allocated keys for the nodes. In this proof of concept there is only one middle node and an egress node
    // so the shape is [2][key-length]
    uint8_t ciphertext[128];
    uint8_t plaintext[128];
    printf("\n----------Encrypting----------\n");
    for (int i = 0; i < SID_NO; i++)
    {
        printf("---Iteration: %d---\n", i);
        printf("original text is:\n");
        for (int j = 0; j < HMAC_MAX_LENGTH; j++)
        {
            printf("%02x", hmac_out[j]);
        }
        printf("\n");
        printf("PVF size : %ld\n", strnlen(hmac_out, HMAC_MAX_LENGTH));
        int cipher_len = encrypt(hmac_out, HMAC_MAX_LENGTH, k_pot_in[i], nonce, ciphertext);
        printf("The cipher length is : %d\n", cipher_len);

        printf("Ciphertext is : \n");
        BIO_dump_fp(stdout, (const char *)ciphertext, cipher_len);
        memcpy(hmac_out, ciphertext, 32);
        printf("\n");
    }
}

int decrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t pvf_out[32])
{
    // k_pot_in is a 2d array of strings holding statically allocated keys for the nodes. In this proof of concept there is only one middle node and an egress node
    // so the shape is [2][key-length]
    uint8_t plaintext[128];
    int cipher_len = 32;
    printf("\n----------Decrypting----------\n");
    for (int i = SID_NO - 1; i >= 0; i--)
    {
        printf("---Iteration: %d---\n", i);
        int dec_len = decrypt(pvf_out, cipher_len, k_pot_in[i], nonce, plaintext);
        printf("Dec len %d\n", dec_len);
        printf("original text is:\n");
        for (int j = 0; j < HMAC_MAX_LENGTH; j++)
        {
            printf("%02x", pvf_out[j]);
        }
        printf("\n");
        memcpy(pvf_out, plaintext, 32);
        printf("Decrypted text is : \n");
        BIO_dump_fp(stdout, (const char *)pvf_out, dec_len);
    }
}

int main(int argc, char *argv[])
{

    printf("Enter  (0-1): ");
    if (scanf("%u", &operation_bypass_bit) == 1)
    { // Read an unsigned integer
        if (operation_bypass_bit > 1 || operation_bypass_bit < 0)
        {
            printf("You entered: %u\n", operation_bypass_bit);
            rte_exit(EXIT_FAILURE, "Invalid argument\n");
        }
        else
        {
            printf("You entered: %u\n", operation_bypass_bit);
        }
    }

    struct rte_mempool *mbuf_pool;
    uint16_t port_id = 0;
    uint16_t tx_port_id = 1;

    static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
        .name = "example_bbdev_dynfield_tsc",
        .size = sizeof(tsc_t),
        .align = alignof(tsc_t),
    };

    // Initialize the Environment Abstraction Layer (EAL)
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    // Check that there is at least one port available
    uint16_t portcount = 0;
    if (rte_eth_dev_count_avail() == 0)
    {
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    }
    else
    {
        portcount = rte_eth_dev_count_total();
        printf("number of ports: %d \n", (int)portcount);
    }

    // Create a memory pool to hold the mbufs
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(),
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE + EXTRA_SPACE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    tsc_dynfield_offset =
        rte_mbuf_dynfield_register(&tsc_dynfield_desc);
    if (tsc_dynfield_offset < 0)
        rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");

    // Initialize the port
    if (port_init(port_id, mbuf_pool) != 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port_id);
    }
    else
    {
        rte_eth_add_rx_callback(port_id, 0, add_timestamps, NULL);
        display_mac_address(port_id);
    }

    if (port_init(tx_port_id, mbuf_pool) != 0)
    {

        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", tx_port_id);
    }
    else
    {
        rte_eth_add_tx_callback(tx_port_id, 0, calc_latency, NULL);
        display_mac_address(tx_port_id);
    }
    printf("Capturing packets on port %d...\n", port_id);

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
                printf("ip4\n");
                break;
            case RTE_ETHER_TYPE_IPV6:
                switch (operation_bypass_bit)
                {
                case 0:
                    printf("\n#######################################################\n");
                    // 2 options here the packets already containing srh and the packets does not contain
                    // TODO CHECK İP6 hdr if next_header field is 43 to determine if the packet is srh
                    add_custom_header6(mbuf);

                    struct ipv6_srh *srh;
                    struct hmac_tlv *hmac;
                    struct pot_tlv *pot;
                    // realigning the hmac header since we added new headers the address is changed(bu alignment ı beğenmiyorum değiştir)
                    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
                    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
                    srh = (struct ipv6_srh *)(ipv6_hdr + 1); // SRH follows IPv6 header
                    hmac = (struct hmac_tlv *)(srh + 1);
                    pot = (struct pot_tlv *)(hmac + 1);

                    uint8_t hmac_out[HMAC_MAX_LENGTH];
                    uint8_t k_hmac_ie[] = "my-hmac-key-for-pvf-calculation";
                    uint8_t nonce[NONCE_LENGTH];
                    size_t key_len = strlen((char *)k_hmac_ie);

                    // FOR PROOF OF CONCEPT THIS IS NOT DYNAMIC
                    // NORMALLY THİS SHOULD BE DYNAMIC ACCORDING TO THE NODES IN THE TOPOLOGY OR SPECIFIALLY ESPECTED PATH OF THE PACKET
                    // can use malloc *
                    char target_ip[16];
                    inet_pton(AF_INET6, "2001:db8:1::1", target_ip);

                    if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, target_ip, INET6_ADDRSTRLEN) == NULL)
                    {
                        perror("inet_ntop failed");
                        return 1;
                    }

                    printf("IPv6 Address (string format): %s\n", target_ip);

                    const char *ip1 = "2001:db8:1::6";
                    const char *ip2 = "2001:db8:1::8";
                    const char *ip3 = "2001:db8:1::10";
                    uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH];

                    if (strncmp(target_ip, ip2, INET6_ADDRSTRLEN) == 0)
                    {
                        uint8_t temp[SID_NO][HMAC_MAX_LENGTH] = {
                            "qqwwqqwwqqwwqqwwqqwwqqwwqqwwqqw",
                            "eerreerreerreerreerreerreerreer"};
                        memcpy(k_pot_in, temp, sizeof(temp));
                    }
                    else if (strncmp(target_ip, ip1, INET6_ADDRSTRLEN) == 0)
                    {
                        uint8_t temp[SID_NO][HMAC_MAX_LENGTH] = {
                            "ttyyttyyttyyttyyttyyttyyttyytty",
                            "eerreerreerreerreerreerreerreer"};
                        memcpy(k_pot_in, temp, sizeof(temp));
                    }
                    // IPERF SETUP CODE FORWARD IT TO SERVER BY SWAPPING MAC ADDRESSES SO THE VIRTUAL SWITCH CAN FORWARD IT TO NEXT MACHINE
                    if (strncmp(target_ip, ip3, INET6_ADDRSTRLEN) == 0)
                    {
                        uint8_t temp[SID_NO][HMAC_MAX_LENGTH] = {
                            "qqwwqqwwqqwwqqwwqqwwqqwwqqwwqqw",
                            "eerreerreerreerreerreerreerreer"};
                        memcpy(k_pot_in, temp, sizeof(temp));

                        
                        struct rte_ether_addr mac_addr = {{0x08, 0x00, 0x27, 0xC6, 0x79, 0x2A}}; // rx port of middle node
                        rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
                        rte_ether_addr_copy(&mac_addr, &eth_hdr->dst_addr);
                    }

                    // key of the last node is first

                    // Compute HMAC
                    if (calculate_hmac(ipv6_hdr->src_addr, srh, hmac, k_hmac_ie, key_len, hmac_out) == 0)
                    {
                        printf("HMAC Computation Successful\n");
                        printf("HMAC: ");
                        for (int i = 0; i < HMAC_MAX_LENGTH; i++)
                        {
                            printf("%02x", hmac_out[i]);
                        }
                        // Write the hmac value in hmac header
                        printf("\n");
                        memcpy(hmac->hmac_value, hmac_out, 32);
                        printf("HMAC value inserted to srh_hmac header\n");
                    }
                    else
                    {
                        printf("HMAC Computation Failed\n");
                    }

                    if (generate_nonce(nonce) != 0)
                    {
                        printf("Nonce generation failed retuning\n ");
                        return 1;
                    }
                    encrypt_pvf(k_pot_in, nonce, hmac_out);

                    printf("Ecrypted PVF before writing to the header: ");
                    for (int i = 0; i < HMAC_MAX_LENGTH; i++)
                    {
                        printf("%02x", hmac_out[i]);
                    }
                    // Write the hmac value in hmac header
                    printf("\n");
                    memcpy(pot->encrypted_hmac, hmac_out, 32);
                    memcpy(pot->nonce, nonce, 16);
                    printf("Encrypted PVF and nonce values inserted to pot header\n");

                    // Decrypt fpr testing purposes, this is the task for middle and egress nodes
                    // decrypt_pvf(k_pot_in, nonce, hmac_out);

                    // send the packets back with added custom header
                    if (rte_eth_tx_burst(tx_port_id, 0, &mbuf, 1) == 0)
                    {
                        printf("Error sending packet\n");
                        rte_pktmbuf_free(mbuf);
                    }
                    else
                    {
                        printf("IPV6 packet sent\n");
                    }
                    rte_pktmbuf_free(mbuf);
                    printf("#######################################################\n");
                    break;
                case 1:
                    printf("All operations are bypassed. \n");
                    if (rte_eth_tx_burst(tx_port_id, 0, &mbuf, 1) == 0)
                    {
                        printf("Error sending packet\n");
                        rte_pktmbuf_free(mbuf);
                    }
                    else
                    {
                        printf("IPV6 packet sent\n");
                    }
                    rte_pktmbuf_free(mbuf);
                    break;

                default:
                    // printf("\nonly ip4 or ip6 ethernet headers accepted\n");
                    break;
                }
                // Free the mbuf after processing
                rte_pktmbuf_free(mbuf);
            }
        }
    }

    return 0;
}
