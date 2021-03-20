#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

//
// include
//
#include <stdint.h>
#include <netinet/in.h> // in_addr
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

//
// define
// 
#define MAX_DHCP_CHADDR_LEN     16
#define MAX_DHCP_SNAME_LEN      64
#define MAX_DHCP_FILE_LEN       128
#define MAX_DHCP_OPTIONS_LEN    312

/* Message Operation Code */
#define BOOTREQUEST 1
#define BOOTREPLY   2

/* DHCP Option Code */
#define DHCP_OPTION_MESSAGE_TYPE            53
#define DHCP_OPTION_SUBNET_MASK             1
#define DHCP_OPTION_ROUTER                  3
#define DHCP_OPTION_DNS_SERVER              6
#define DHCP_OPTION_HOST_NAME               12
#define DHCP_OPTION_DOMAIN_NAME             15
#define DHCP_OPTION_BROADCAST_ADDRESS       28
#define DHCP_OPTION_REQUESTED_ADDRESS       50
#define DHCP_OPTION_LEASE_TIME              51
#define DHCP_OPTION_SERVER_IDENTIFIER       54
#define DHCP_OPTION_PARAMETER_REQUEST       55
#define DHCP_OPTION_RENEWAL_TIME            58
#define DHCP_OPTION_REBINDING_TIME          59
#define DHCP_OPTION_TFTP_SERVER_NAME        66
#define DHCP_OPTION_BOOT_FILE_NAME          67
#define DHCP_OPTION_RELAY_AGENT_INFORMATION 82

/*Option_53 = Message Type */
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_DECLINE    4
#define DHCP_ACK        5
#define DHCP_NAK        6
#define DHCP_RELEASE    7
#define DHCP_INFORM     8
#define DHCP_FORCERENEW 9

#define DHCP_INFINITE_TIME 0xFFFFFFFF
 
#define DHCP_BROADCAST_FLAG 32768 //0b10000000

/* UDP Port Number */
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
 
/* DHCP_htype & DHCP_hle */
#define HTYPE_ETHER     1
#define HTYPE_ETHER_LEN 6

/* DHCP fixed length field size */
#define FIXED_FIELD_SIZE    236

/* Max DHCP packet size */
#define MAX_DHCP_PACKET_SIZE    548

//
// typedef
//
typedef struct sockaddr_in  TS_SOCKADDR_IN;
typedef struct in_addr      TS_IN_ADDR;
typedef struct sockaddr     TS_SOCKADDR;
typedef struct ethhdr       TS_ETHHDR;

//
// struct
//
typedef struct {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    TS_IN_ADDR ciaddr;
    TS_IN_ADDR yiaddr;
    TS_IN_ADDR siaddr;
    TS_IN_ADDR giaddr;
    uint8_t chaddr[MAX_DHCP_CHADDR_LEN];
    char sname[MAX_DHCP_SNAME_LEN];
    char file[MAX_DHCP_FILE_LEN];
    u_char options[MAX_DHCP_OPTIONS_LEN];
} __attribute__((packed)) TS_DHCP_PACKET;

/*
typedef struct {
    struct ether_header eth;
    struct iphdr ip;
    struct udphdr udp;
    u_char dhcp_data[MAX_DHCP_PACKET_SIZE];
} __attribute__((packed)) TS_ETH_IP_UDP_HEADER;
*/

struct udp_packet{
  struct ether_header eh;
  struct iphdr ip;
  struct udphdr udp;
  uint8_t data[MAX_DHCP_PACKET_SIZE];
} __attribute__ ((__packed__));
 
struct pseudo_header{
  uint32_t saddr;
  uint32_t daddr;
  uint8_t  reserved;
  uint8_t  protocol;
  uint16_t len;
} __attribute__ ((__packed__));
 
struct pseudo_udp{
  struct pseudo_header ip;
  struct udphdr udp;
  uint8_t data[MAX_DHCP_PACKET_SIZE];
} __attribute__ ((__packed__));

#endif // DHCP_SERVER_H