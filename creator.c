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

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define CUSTOM_HEADER_TYPE 0x0833
#define SID_NO 2        // Total 3 dpdk runnning nodes. 2 of them are sid1 and sid0(egress)
#define NONCE_LENGTH 16 // AES uses 16 bytes of iv

#define HMAC_MAX_LENGTH 32 // Truncate HMAC to 32 bytes if needed

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
    // Definitions
    struct ipv6_srh *srh_hdr;
    struct hmac_tlv *hmac_hdr;
    struct pot_tlv *pot_hdr;
    struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
    void *rest_of_packet = (ipv6_hdr + 1);

    // save the headers that will be deleted
    struct rte_ether_hdr tmp_eth;
    struct rte_ipv6_hdr tmp_ip6;
    memcpy(&tmp_eth, eth_hdr_6, sizeof(*eth_hdr_6));
    memcpy(&tmp_ip6, ipv6_hdr, sizeof(*ipv6_hdr));

    printf("did i successfully copy the eth header 6, %02X:%02X:%02X:%02X:%02X:%02X\n",
           tmp_eth.src_addr.addr_bytes[0], tmp_eth.src_addr.addr_bytes[1],
           tmp_eth.src_addr.addr_bytes[2], tmp_eth.src_addr.addr_bytes[3],
           tmp_eth.src_addr.addr_bytes[4], tmp_eth.src_addr.addr_bytes[5]);

    // Remove ethernet and ip6 headers
    rte_pktmbuf_adj(pkt, (uint16_t)sizeof(struct rte_ether_hdr));
    rte_pktmbuf_adj(pkt, (uint16_t)sizeof(struct rte_ipv6_hdr));

    // Add POT , HMAC and SRH headers respectively

    //hmac_hdr = (struct hmac_tlv *)rte_pktmbuf_prepend(pkt, sizeof(struct hmac_tlv));
    //srh_hdr = (struct ipv6_srh *)rte_pktmbuf_prepend(pkt, sizeof(struct ipv6_srh));
    pot_hdr = (struct pot_tlv *)rte_pktmbuf_prepend(pkt, sizeof(struct pot_tlv));
    if (pot_hdr == NULL)
    {
        printf("asdasdasdasdasdasd");
        fflush(stdout);
    };

    // Populate the fields
    /*
        pot_hdr->type = 1;  // made it up since it is tbd
        pot_hdr->length = 48; // 32 b PVF + 16 b nonce
        pot_hdr->reserved = 0;
        pot_hdr->nonce_length = 16;
        pot_hdr->key_set_id = rte_cpu_to_be_32(1234);
        // Initialize the nonce and PVF values (32 bytes of 0x01)
        memset(pot_hdr->nonce, 0, sizeof(pot_hdr->nonce));
        memset(pot_hdr->encrypted_hmac, 0, sizeof(pot_hdr->encrypted_hmac));

        printf("Size of POT header: %lu\n", sizeof(struct pot_tlv));
        printf("Size of HMAC header: %lu\n", sizeof(struct hmac_tlv));
        printf("Size of SRH header: %lu\n", sizeof(struct ipv6_srh));
    */
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

    // Add the ip6 and ethernet headers respectively
    struct rte_ipv6_hdr *new_ip6_ptr = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct rte_ipv6_hdr));
    struct rte_ether_hdr *new_ether_ptr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct rte_ether_hdr));

    // Set added headers to saved headers
    memcpy(new_ether_ptr, &tmp_eth, sizeof(tmp_eth));
    memcpy(new_ip6_ptr, &tmp_ip6, sizeof(tmp_ip6));

    new_ip6_ptr->proto = 43;

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
int calculate_pvf(uint8_t *k_hmac_ie, uint8_t *hmac, uint8_t *pvf_out)
{
    // Calculate PVF
    unsigned int hmac_len;

    size_t key_len = strlen((char *)k_hmac_ie);
    uint8_t *digest = (uint8_t *)HMAC(EVP_sha256(), k_hmac_ie, key_len, hmac, HMAC_MAX_LENGTH, NULL, &hmac_len);
    printf("PVF length is: %d\n", hmac_len);
    if (!digest)
    {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "PVF computation failed\n");
        return -1;
    }

    // Truncate or pad the HMAC to 32 bytes
    if (hmac_len > HMAC_MAX_LENGTH)
    {
        memcpy(pvf_out, digest, HMAC_MAX_LENGTH);
    }
    else
    {
        memcpy(pvf_out, digest, hmac_len);
        memset(pvf_out + hmac_len, 0, HMAC_MAX_LENGTH - hmac_len); // Pad with zeros
    }

    printf("The PVF is: ");
    for (int i = 0; i < HMAC_MAX_LENGTH; i++)
    {
        printf("%02x", pvf_out[i]);
    }
    // Write the hmac value in hmac header
    printf("\n");
}

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

void encrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t pvf_out[32])
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
            printf("%02x", pvf_out[j]);
        }
        printf("\n");
        printf("PVF size : %ld\n", strnlen(pvf_out, HMAC_MAX_LENGTH));
        printf("The cipher length is : %d\n", encrypt(pvf_out, strnlen(pvf_out, HMAC_MAX_LENGTH), k_pot_in[i], nonce, ciphertext));
        int cipher_len = encrypt(pvf_out, HMAC_MAX_LENGTH, k_pot_in[i], nonce, ciphertext);
        printf("Ciphertext is : \n");
        BIO_dump_fp(stdout, (const char *)ciphertext, cipher_len);
        memcpy(pvf_out, ciphertext, 32);
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
                break;
            case RTE_ETHER_TYPE_IPV6:
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

                uint8_t key[] = "your-pre-shared-key"; // Replace with actual pre-shared key
                size_t key_len = strlen((char *)key);
                uint8_t hmac_out[HMAC_MAX_LENGTH];
                uint8_t pvf_out[HMAC_MAX_LENGTH];
                uint8_t k_hmac_ie[] = "my-hmac-key-for-pvf-calculation";
                uint8_t nonce[NONCE_LENGTH];

                // FOR PROOF OF CONCEPT THIS IS NOT DYNAMIC
                // NORMALLY THİS SHOULD BE DYNAMIC ACCORDING TO THE NODES IN THE TOPOLOGY OR SPECIFIALLY ESPECTED PATH OF THE PACKET
                // can use malloc *
                uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH] = {
                    "qqwwqqwwqqwwqqwwqqwwqqwwqqwwqqw", // eggress node key
                    "eerreerreerreerreerreerreerreer"  // middle node key
                };
                // key of the last node is first

                // Compute HMAC bunu burdan al başka biyere koy
                if (calculate_hmac(ipv6_hdr->src_addr, srh, hmac, key, key_len, hmac_out) == 0)
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

                calculate_pvf(k_hmac_ie, hmac_out, pvf_out);

                if (generate_nonce(nonce) != 0)
                {
                    printf("Nonce generation failed retuning\n ");
                    return 1;
                }
                encrypt_pvf(k_pot_in, nonce, pvf_out);

                printf("Ecrypted PVF before writing to the header: ");
                for (int i = 0; i < HMAC_MAX_LENGTH; i++)
                {
                    printf("%02x", pvf_out[i]);
                }
                // Write the hmac value in hmac header
                printf("\n");
                memcpy(pot->encrypted_hmac, pvf_out, 32);
                memcpy(pot->nonce, nonce, 16);
                printf("Encrypted PVF and nonce values inserted to pot header\n");

                // Decrypt fpr testing purposes, this is the task for middle and egress nodes
                decrypt_pvf(k_pot_in, nonce, pvf_out);

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
            default:
                // printf("\nonly ip4 or ip6 ethernet headers accepted\n");
                break;
            }
            // Free the mbuf after processing
            rte_pktmbuf_free(mbuf);
        }
    }

    return 0;
}
