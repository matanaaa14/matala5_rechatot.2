
#include <stdio.h>
#include <string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>

/**********************************************
 * Listing 12.2: Packet Capturing using raw socket
 **********************************************/

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include<netinet/tcp.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <time.h>
static clock_t start;  
static int flag=0;
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
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


struct helpStruct {
    uint32_t unixtime;
    uint16_t length;
    union{
        uint16_t flags;
        uint16_t reserved:3,c_flag:1,s_flag:1,t_flag:1,status:10;
    };
    uint16_t cache;
    uint16_t spacing;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
   
  FILE* fp;
  fp=fopen("packet.txt","a+");
  if(fp==NULL){
    perror("error open file");
    exit(1);
  }


  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
  
  struct tcphdr *tcph=(struct tcphdr*)(packet +sizeof(struct ethheader)+ip->iph_ihl*4);

    struct helpStruct *help=(struct helpStruct *)
    (packet + sizeof(struct ethheader) + ip->iph_ihl*4 + tcph->th_off*4);
    const u_char *arr = (packet + sizeof(struct ethheader) 
    + ip->iph_ihl*4 + tcph->th_off*4 + 12);
    const unsigned int arr_length = (ntohs(help->length));  
    help->flags=ntohs(help->flags);
    if(tcph->psh!=1)
      return;
    fprintf(fp,"        source_ip: %s\n", inet_ntoa(ip->iph_sourceip));//ip source  
    fprintf(fp,"        dest_ip: %s\n", inet_ntoa(ip->iph_destip));//ip dest 
    fprintf(fp,"        source_port: %u\n", ntohs(tcph->source));//source port 
    fprintf(fp,"        dest_port: %u\n", ntohs(tcph->dest));//dest port
    fprintf(fp,"        type flag: %hu\n",((help->t_flag>>10) & 1));//type
    fprintf(fp,"        timestemp: %u\n",ntohl(help->unixtime));
    fprintf(fp,"        length: %u\n",ntohs(help->length));
    fprintf(fp,"        cache control: %hu\n",ntohs(help->cache));
    fprintf(fp,"        status code: %hu\n",ntohs(help->status));
    fprintf(fp,"        cache flag: %hu\n",((help->c_flag>>12) & 1));
    fprintf(fp,"        steps flag: %hu\n",((help->s_flag>>11) & 1));

 
    
    for (int i = 0; i < arr_length; i++) {
      if(i%20==0)
        fprintf(fp,"\n");
        fprintf(fp,"  %02x", arr[i] & 0xff);
    }        
    fprintf(fp,"\n");

    /* determine protocol */
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            fprintf(fp,"   Protocol: TCP\n");
            fclose(fp);
            return;
        case IPPROTO_UDP:
            fprintf(fp,"   Protocol: UDP\n");
            fclose(fp);
            return;
        case IPPROTO_ICMP:
            fprintf(fp,"   Protocol: ICMP\n");
            fclose(fp);
            return;
        default:
            fprintf(fp,"   Protocol: others\n");
            fclose(fp);
            return;
    }
  }
}


int main()
{ printf("check1\n");//check
 

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;
  printf("check2\n");//check
  bzero(errbuf,sizeof(errbuf));
  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 
  printf("check3\n");//check
  //me:
  char zero[PCAP_ERRBUF_SIZE];
  bzero(zero,sizeof(zero));
  if(strcmp(errbuf,zero)==0)//check
    printf("error\n");
  printf("check5\n");//check
  // Step 2: Compile filter_exp into BPF psuedo-code
  if(pcap_compile(handle, &fp, filter_exp, 0, net)!=0){
    perror("error in compile\n");
  }
  printf("check6\n");//check      
  pcap_setfilter(handle, &fp);                             
  printf("check4\n");//check


  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
