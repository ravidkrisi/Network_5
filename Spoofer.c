#include "interface.h"


int main (){

  char buffer[BUFFERSIZE];

  memset(buffer, 0, BUFFERSIZE);

  /*********************************************************
    Step 1: Fill in the ICMP header.
  ********************************************************/
  struct icmpheader *icmp = (struct icmpheader *) 
                            (buffer + sizeof(struct ipheader));
  icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

  // Calculate the checksum for integrity
  icmp->icmp_chksum = 0;
  icmp->icmp_chksum = in_cksum((unsigned short *)icmp, 
                                sizeof(struct icmpheader));

  /*********************************************************
    Step 2: Fill in the IP header.
  ********************************************************/
  struct ipheader *ip = (struct ipheader *) buffer;
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr("8.8.8.8");
  ip->iph_destip.s_addr = inet_addr("10.0.2.15");
  ip->iph_protocol = IPPROTO_ICMP; 
  ip->iph_len = htons(sizeof(struct ipheader) + 
                      sizeof(struct icmpheader));

  /*********************************************************
    Step 3: Finally, send the spoofed packet
  ********************************************************/
  send_raw_ip_packet (ip);

  return 0;
}
