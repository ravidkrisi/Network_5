#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include<string.h>	
#include<netinet/ip_icmp.h>	
#include<netinet/udp.h>	
#include<netinet/tcp.h>	
#include<netinet/ip.h>
#include <string.h>
#include <unistd.h>

#define BUFFERSIZE 1024

  struct apphdr{
    uint32_t unixtime;
    uint16_t length;
    uint16_t reserved: 3, c_flags:1, s_flag:1, t_flag:1, status:10;
    uint16_t cache;
    uint16_t padding;
 };

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

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmpid;//Used for identifying request
  unsigned short int icmpseq;    //Sequence number
};

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

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info));
    printf("send packet\n");
    close(sock);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void spoof_icmp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void tcp_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
