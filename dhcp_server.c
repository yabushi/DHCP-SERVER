#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>         // socket()
#include <arpa/inet.h>          // inet_aton()
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>

#include "dhcp_server.h"

#define FALSE -1
#define TRUE 0

#define CLIENT_IP_ADDR  ("192.168.3.19")
#define SUBNET_MASK     ("255.255.255.0")
#define DEFAULT_GATEWAY ("192.168.3.16")
#define BROADCAST_ADDR  ("255.255.255.255")
#define SERVER_ID       ("192.168.3.16")
#define SERVER_NIC      "eth0"

/**
 * @brief   open socket for dhcp server.
 * 
 * @retval  sock    socket descripter
 * @retval  -1      False
 **/
int open_socket(void) {
#if 0

    int sock = -1;
    TS_SOCKADDR_IN ts_sockaddr_in;
    // sockaddr init
    memset(&ts_sockaddr_in, 0, sizeof(TS_SOCKADDR_IN));
    ts_sockaddr_in.sin_family      = AF_INET;
    ts_sockaddr_in.sin_port        = htons(DHCP_SERVER_PORT);
    ts_sockaddr_in.sin_addr.s_addr = INADDR_ANY;

    // make socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return FALSE;
    }
    printf("socket : %d\n", sock);

    // can use broadcast
    int ret;
    int flag = DHCP_BROADCAST_FLAG;
    ret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void*)&flag, sizeof(int));
    if (ret != 0) {
        perror("setsockopt");
        close(sock);
        return FALSE;
    }

    // bind socket
    ret = bind(sock, (TS_SOCKADDR*)&ts_sockaddr_in, sizeof(TS_SOCKADDR_IN));
    if (ret == -1) {
        perror("bind");
        close(sock);
        return FALSE;
    }

    return sock;
#else
    struct sockaddr_ll sll;
    struct ifreq ifr;
    int soc = -1;

    if((soc=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
        perror("[-]Failed to open socket");
        return FALSE;
    }

    strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name)-1);
    if(ioctl(soc, SIOCGIFINDEX, &ifr)<0){
        perror("[-]Failed ioctl(SIOCGIFINDEX)");
        close (soc);
        return FALSE;
    }

    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if(bind(soc, (struct sockaddr *)&sll, sizeof(sll))<0){
        perror("[-]Failed bind");
        close(soc);
        return FALSE;
    }
    
    return soc;
#endif 
}

uint16_t checksum(uint8_t *data, size_t len)
{
    uint32_t sum, c;
    uint16_t val, *ptr;
    sum = 0;
    ptr = (uint16_t *)data;
    for(c=len; c>=len; c-=2){
        sum += (*ptr);
        if(sum&0x80000000){
        sum = (sum & 0xFFFF)+(sum>>16);
        }
        ptr++;
    }
    if(c==-1){
        val=0;
        memcpy(&val, ptr, sizeof(uint8_t));
        sum += val;
    }
    while(sum>>16){
        sum =(sum & 0xFFFF)+(sum>>16);
    }
    if(sum == 0xFFFF){
        return sum;
    }else{
        return ~sum;
    }

    return sum;  
}

u_char *get_mac(int soc, char *device)
{
    struct ifreq ifr;
    u_char *mac;
    
    memcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name)-1);
    if(ioctl(soc, SIOCGIFHWADDR, &ifr)<0){
        perror("[-]Falied ioctl(SIOCGIFHWADDR)");
        return NULL;
    }
    
    mac = (u_char *)ifr.ifr_hwaddr.sa_data;
    printf("[+]Success got MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", *mac, *(mac+1), *(mac+2), *(mac+3), *(mac+4), *(mac+5));
    
    return mac;
}

int send_udp_from_raw(int soc, char *device, const uint8_t *data, size_t size, char* dest_ip, char* dest_ether)
{
    uint8_t buf[sizeof(struct udp_packet)];
    uint8_t *p;
    struct udp_packet udp;
    struct pseudo_udp pse_udp;
    size_t total;

//    printf("dest_ip : %d.%d.%d.%d\n", *dest_ip, *(dest_ip + 1), *(dest_ip + 2), *(dest_ip + 3));

    memset(&pse_udp, 0, sizeof(pse_udp));
    inet_pton(AF_INET, SERVER_ID, &pse_udp.ip.saddr);
    memcpy(&pse_udp.ip.daddr, dest_ip, sizeof(uint32_t));
    pse_udp.ip.reserved = 0;
    pse_udp.ip.protocol = 17;
    pse_udp.ip.len = htons(sizeof(struct udphdr)+size);
    pse_udp.udp.source = htons(DHCP_SERVER_PORT);
    pse_udp.udp.dest = htons(DHCP_CLIENT_PORT);
    pse_udp.udp.len = htons(sizeof(struct udphdr)+size);
    pse_udp.udp.check = 0;
    memset(pse_udp.data, 0, sizeof(pse_udp.data));
    memcpy(pse_udp.data, data, size);

    pse_udp.udp.check = checksum((u_char *)&pse_udp, sizeof(struct pseudo_header)+sizeof(struct pseudo_udp)+size);

    memset(&udp, 0, sizeof(udp));
    memcpy(&udp.udp, &pse_udp.udp, sizeof(struct udphdr));
    memcpy(udp.data, pse_udp.data, sizeof(udp.data));

    udp.ip.version = 4;
    udp.ip.ihl = 20/4;
    udp.ip.tos = 0;
    udp.ip.tot_len = htons(sizeof(struct iphdr)+sizeof(struct udphdr)+size);
    udp.ip.id = 0;
    udp.ip.frag_off = 0;
    udp.ip.ttl = 64;
    udp.ip.protocol = IPPROTO_UDP;
    udp.ip.check = 0;
    inet_pton(AF_INET, SERVER_ID, &udp.ip.saddr);
    memcpy(&udp.ip.daddr, dest_ip, sizeof(uint32_t));

    udp.ip.check = checksum((uint8_t *)&udp.ip, sizeof(struct iphdr));

    memcpy(udp.eh.ether_dhost, dest_ether, 6);
#if 0
    printf("dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           *dest_ether, *(dest_ether + 1), *(dest_ether + 2), 
           *(dest_ether + 3), *(dest_ether + 4), *(dest_ether + 5));
#endif
    memcpy(udp.eh.ether_shost, get_mac(soc, device), 6);
    udp.eh.ether_type = htons(ETHERTYPE_IP);

    memset(buf, 0, sizeof(buf));
    p = buf;

    memcpy(p, &udp.eh,sizeof(struct ether_header));
    p += sizeof(struct ether_header);
    memcpy(p, &udp.ip, sizeof(struct iphdr));
    p += sizeof(struct iphdr);
    memcpy(p, &udp.udp, sizeof(struct udphdr));
    p += sizeof(struct udphdr);
    memcpy(p, udp.data, size);
    p += size;
    total = p-buf;
    
#if 0
    TS_DHCP_PACKET dhcp_packet = {};
    memcpy(&dhcp_packet, &data, sizeof(TS_DHCP_PACKET));
    if(sendto(soc, buf, total, 0, &dhcp_packet.chaddr, sizeof(dhcp_packet.chaddr))==-1){
        perror("[-]Failed to send");
        return FALSE;
    }
#else
    if(send(soc, buf, total, 0)==-1){
        perror("[-]Failed to send");
        return FALSE;
    }
#endif
    return size;
}

/**
 * @brief       set DHCP options field.
 * 
 * @param[out]  opt_ptr 
 * @param[in]   opt_type    options type
 * @param[in]   opt_len     length of options field context
 * @param[in]   opt_context options context
 * @param[out]  options_len total options field length
 * 
 * @retval      none
 **/
void set_DHCP_option(u_char** opt_ptr, const int opt_type, 
                     const u_char opt_len, const int opt_context, u_int32_t* options_len) {
    **opt_ptr = opt_type;
    (*opt_ptr)++;
    // **opt_ptr = opt_len;
    memcpy(*opt_ptr, &opt_len, 1);
    (*opt_ptr)++;
    memcpy(*opt_ptr, &opt_context, opt_len);
    *opt_ptr += opt_len;
    *options_len += (2 + opt_len); // 2 == option type field + option length field
}

void dump_DHCP_packet(TS_DHCP_PACKET ts_dhcp_packet) {
    printf("--------------------\n");

    // op
    printf("op     : %d\n", ts_dhcp_packet.op);

    // xid
    printf("xid    : %x\n", ts_dhcp_packet.xid);

    // flags
    printf("flags  : %d\n", ts_dhcp_packet.flags);

    // ciaddr
    printf("ciaddr : %s\n", inet_ntoa(ts_dhcp_packet.ciaddr));

    // yiaddr
    printf("yiaddr : %s\n", inet_ntoa(ts_dhcp_packet.yiaddr));

    // siaddr
    printf("siaddr : %s\n", inet_ntoa(ts_dhcp_packet.siaddr));

    // giaddr
    printf("giaddr : %s\n", inet_ntoa(ts_dhcp_packet.giaddr));

    // chaddr
    printf("chaddr : %02x:%02x:%02x:%02x:%02x:%02x", 
           *(ts_dhcp_packet.chaddr + 0),
           *(ts_dhcp_packet.chaddr + 1),
           *(ts_dhcp_packet.chaddr + 2),
           *(ts_dhcp_packet.chaddr + 3),
           *(ts_dhcp_packet.chaddr + 4),
           *(ts_dhcp_packet.chaddr + 5)
           );
        
    printf("\n");
}

void dump_udp_header(struct udphdr* udp_hdr) {
    printf("----- udp_header -----\n");

    // sport
    printf("sport  : %d\n", ntohs(udp_hdr->source));

    // dport
    printf("dport  : %d\n", ntohs(udp_hdr->dest));

    // ulen
    printf("ulen   : %d\n", ntohs(udp_hdr->len));
}

void dump_ip_header(struct iphdr* ip_hdr) {
    printf("----- ip_header -----\n");

    // version
    printf("version: %d\n", ip_hdr->version);

    // header length
    printf("header_len: %d\n", ip_hdr->ihl);

    // tos
    printf("tos   : %d\n", ip_hdr->tos);

    // total length
    printf("tot_len: %u\n", ntohs(ip_hdr->tot_len));

    // id
    printf("id    : %u\n", ntohs(ip_hdr->id));

    // flag
    printf("flag  : %d\n", (ip_hdr->frag_off >> 5));

    // time to live
    printf("ttl    : %d\n", ip_hdr->ttl);

    // protocol
    printf("protocol: %d : 17 = udp\n", ip_hdr->protocol);

    // saddr
    TS_IN_ADDR inaddr = {};
    memcpy(&inaddr, &ip_hdr->saddr, sizeof(TS_IN_ADDR));
    printf("saddr : %s\n", inet_ntoa(inaddr));
    
    // daddr
    memcpy(&inaddr, &ip_hdr->daddr, sizeof(TS_IN_ADDR));
    printf("daddr : %s\n", inet_ntoa(inaddr));
}

void dump_ether_header(struct ether_header* eth_hdr) {
    printf("----- ether_header -----\n");

    // shost
    printf("shost : %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth_hdr->ether_shost[0],
           eth_hdr->ether_shost[1],
           eth_hdr->ether_shost[2],
           eth_hdr->ether_shost[3],
           eth_hdr->ether_shost[4],
           eth_hdr->ether_shost[5]
           );

    // dhost
    printf("dhost : %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth_hdr->ether_dhost[0],
           eth_hdr->ether_dhost[1],
           eth_hdr->ether_dhost[2],
           eth_hdr->ether_dhost[3],
           eth_hdr->ether_dhost[4],
           eth_hdr->ether_dhost[5]
           );

    // type
    printf("type  : %d\n", ntohs(eth_hdr->ether_type));
}

/**
 * @brief   make DHCP response from DHCP request.
 * 
 * @param[out]  response        DHCP response
 * @param[out]  res_len         DHCP response length
 * @param[in]   request         DHCP request
 * @param[in]   req_len
 * @param[out]  ts_send_sockaddr_in 
 * @param[in]   ts_recv_sockaddr_in
 * 
 * @retval  0   success to make DHCP response
 * @retval  -1  faild to make DHCP response
 * @retval  -2  request is not DHCP request
 * 
 **/
int make_DHCP_response(TS_DHCP_PACKET* response, u_int32_t* res_len, 
                       const TS_DHCP_PACKET* request, const u_int32_t req_len,
                       TS_SOCKADDR_IN* ts_send_sockaddr_in, 
                       const TS_SOCKADDR_IN* ts_recv_sockaddr_in) {
    // check arg
    if (response == NULL, request == NULL, 
        ts_send_sockaddr_in == NULL, ts_recv_sockaddr_in == NULL) {
        perror("invalid arg.");
        return -1;
    }
    
    
    // DHCP パケットであることを確認
    u_char magic[] = {0x63, 0x82, 0x53, 0x63};
    int ret = 0;
#if 0
    printf("request->options : %x %x %x %x\n", *request->options, *(request->options + 1), *(request->options + 2), *(request->options + 3));
    printf("magic : %x %x %x %x\n", *magic, *(magic + 1), *(magic + 2), *(magic + 3));
    ret = memcmp(request->options, magic, sizeof(uint32_t));
    if (ret != 0) {
        perror("can not find magic cookie");
        return -1;
    }
#else
    /*
    ret = memcmp(request->options, magic, sizeof(uint32_t));
    if (ret != 0) {
        perror("can not find magic cookie");
        return -1;
    }
    */
#endif

    //
    // set Fixed length data
    //

    // オペレーションコード 1:DHCP_Discovor 2:DHCP_Offer 3:DHCP_Request 5:DHCP_ACK
    response->op = 2;
    // ハードウェアタイプ 1:Ethernet
    response->htype = 1;
    // ハードウェアアドレス(MACアドレス)長
    response->hlen = 6;
    // transaction ID
    response->xid = request->xid;
    // クライアントがDHCPのプロセスを始めてからの時間
//    response->secs = request->secs;
    // 1のとき、サーバからクライアントへはブロードキャストで返信、0のときは、ユニキャスト
    response->flags = request->flags;
    // クライアントがもともとIPアドレスをもっていたとき
    

    // クライアントに割り当てたいIPアドレス
    in_addr_t in_addr_yiddr = inet_addr(CLIENT_IP_ADDR);
    // クライアントに割り当てる予定のIPアドレス
    memcpy(&response->yiaddr, &in_addr_yiddr, sizeof(in_addr_t)); 
    // PXEブート等に使用される
    memcpy(&response->siaddr, &request->siaddr, sizeof(uint32_t)); 
    // リレーエージェントのIPアドレス
    memcpy(&response->giaddr, &request->giaddr, sizeof(uint32_t)); 
    // クライアントのMACアドレス
    memcpy(&response->chaddr, &request->chaddr, sizeof(uint8_t) * 16); 

    //
    // set options
    //
    u_char* res_ptr = &response->options;
    u_int32_t options_len = 0;

    // get DHCP message type from recv packet
    u_char* req_ptr = &request->options;
    req_ptr += 4;
    int recv_DHCP_message_type = 0;
    while (1) {
        if ((res_ptr - request->options) <= (req_len - FIXED_FIELD_SIZE)) {
            printf("not exist DHCP_OPTHION_MESSAGE_TYPE\n");
            return -1;
        }

        if (*req_ptr == DHCP_OPTION_MESSAGE_TYPE) {
            // get DHCP message type
            recv_DHCP_message_type = *(req_ptr + 2);
            break;
        } else {
            // move to next option
            req_ptr += 1;
            req_ptr += *(req_ptr) + 1;
        }
    }

    // Magic Cookie
    memcpy(res_ptr, magic, 4);
    res_ptr += 4;       // 4 = sizeof Magic Cookie
    options_len += 4;

    // DHCP Message Type
    switch (recv_DHCP_message_type)
    {
        case DHCP_DISCOVER:
            set_DHCP_option(&res_ptr, DHCP_OPTION_MESSAGE_TYPE, 1, 
                            DHCP_OFFER, &options_len);
            break;
        case DHCP_REQUEST:
            set_DHCP_option(&res_ptr, DHCP_OPTION_MESSAGE_TYPE, 1, 
                            DHCP_ACK, &options_len);
            break;
        
        default:
            break;
    }

    // DHCP Server Identifier
    u_int32_t server_id = inet_addr(SERVER_ID);
    set_DHCP_option(&res_ptr, DHCP_OPTION_SERVER_IDENTIFIER, 4, server_id, &options_len);

    // IP Address Lease Time (24hour)
    u_int32_t lease_time = ntohl(60 * 60 * 24);
    set_DHCP_option(&res_ptr, DHCP_OPTION_LEASE_TIME, 4, lease_time, &options_len);
    
    // Renewal Time Value (12hour)
    u_int32_t renewal_time = ntohl(60 * 60 * 12);
    set_DHCP_option(&res_ptr, DHCP_OPTION_RENEWAL_TIME, 4, renewal_time, &options_len);

    // Rebinding Time Value (21hour)
    u_int32_t rebinding_time = ntohl(60 * 60 * 21);
    set_DHCP_option(&res_ptr, DHCP_OPTION_REBINDING_TIME, 4, rebinding_time, &options_len);
    
    // Subnet Mask
    u_int32_t subnet_mask = inet_addr(SUBNET_MASK);
    set_DHCP_option(&res_ptr, DHCP_OPTION_SUBNET_MASK, 4, subnet_mask, &options_len);

    // Default Gateway
    u_int32_t default_gateway = inet_addr(DEFAULT_GATEWAY); // Default Gateway
    set_DHCP_option(&res_ptr, DHCP_OPTION_ROUTER, 4, default_gateway, &options_len);

    // END
    *res_ptr = 0xFF;
    res_ptr++;
    options_len++;

    *res_len = FIXED_FIELD_SIZE + options_len;

    return 0;
}

int main(void) {
    int ret = FALSE;
    int sock = -1;

    // open/bind socket
    sock = open_socket();
    if (sock == -1) {
        perror("open_socket");
        return -1;
    }
    printf("Success to open UDP socket : %d\n", sock);

    u_int32_t count = 0;
    printf("Please enter the number of repetitions:");
    scanf("%d", &count);

    while (count > 0) {
        // recv DHCP request, and make DHCP response
        TS_DHCP_PACKET dhcp_packet = {};
        u_int32_t dhcp_len = 0;
        struct udp_packet request = {};
        u_int32_t request_size = 0;
        TS_SOCKADDR_IN ts_send_sockadddr_in;

        while(1) {
            // recv DHCP request
            TS_SOCKADDR_IN ts_recv_sockaddr_in;
            socklen_t addrlen = sizeof(ts_recv_sockaddr_in);
            request_size = recvfrom(sock, &request, sizeof(struct udp_packet), 0, 
                                    (TS_SOCKADDR*)&ts_recv_sockaddr_in, 
                                    &addrlen);
            printf("recv %d Bytes from %s ---------------------\n", 
                   request_size, inet_ntoa(ts_recv_sockaddr_in.sin_addr));

            dump_ether_header(&request.eh);
            dump_ip_header(&request.ip);
            dump_udp_header(&request.udp);

#if 1
            if (ntohs(request.udp.dest) != DHCP_SERVER_PORT) {
                printf("it is not DHCP packet\n");
                continue;
            }
#endif       
            request_size -= sizeof(struct iphdr);
            request_size -= sizeof(struct udphdr);

            // make DHCP response
            int ret = FALSE;
            ret = make_DHCP_response(&dhcp_packet, &dhcp_len, request.data , request_size,
                                     &ts_send_sockadddr_in, &ts_recv_sockaddr_in);
            if (ret == -1) {
                perror("faild to make DHCP response");
            } else {
                printf("success to make DHCP responce\n");
                dump_DHCP_packet(dhcp_packet);
                break;
            }
        }

        // send DHCP response
        int ret = FALSE;
        TS_SOCKADDR_IN ts_responce_sockaddr_in;
        ts_responce_sockaddr_in.sin_family = AF_INET;
        ts_responce_sockaddr_in.sin_port = DHCP_CLIENT_PORT;
        TS_DHCP_PACKET* ts_dhcp_request = (TS_DHCP_PACKET*)&request;
        u_int32_t ciaddr = 0;
        memcpy(&ciaddr, &ts_dhcp_request->ciaddr, sizeof(TS_IN_ADDR));

        if (ciaddr == 0 && ts_dhcp_request->flags != DHCP_BROADCAST_FLAG) {
            // unicast to chaddr and yiaddr
            ts_responce_sockaddr_in.sin_addr.s_addr = inet_addr(CLIENT_IP_ADDR);
            // send
            int size = 0;
            size = send_udp_from_raw(sock, "eth0", &dhcp_packet, dhcp_len, &dhcp_packet.yiaddr, dhcp_packet.chaddr);
            if (size > 0) printf("Success to send.\n");
        } else if (ciaddr != 0 && ts_dhcp_request->flags != DHCP_BROADCAST_FLAG) {
            // unicast to ciaddr
            ts_responce_sockaddr_in.sin_addr = ts_dhcp_request->ciaddr;
            // send
            int size = 0;
            size = send_udp_from_raw(sock, "eth0", &dhcp_packet, dhcp_len, &dhcp_packet.yiaddr, dhcp_packet.chaddr);
            if (size > 0) printf("Success to send.\n");
        } else if (ciaddr == 0 && ts_dhcp_request->flags == DHCP_BROADCAST_FLAG) {
            // broadcast
            ts_responce_sockaddr_in.sin_addr.s_addr = inet_addr(BROADCAST_ADDR);
            
        }
        
        count--;
    }

    // close socket
    close(sock);
    printf("\n");
    printf("Socket closed.\n");

    return 0;
}
