#include "interface.h"

FILE *file;


int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;
 

    //create the log file
    file = fopen("log.txt", "w");
    if(file == NULL)
    {
        perror("error opening file");
        return 1;
    }
    printf("[+]created log file\n");

    //open live pcap session 
    pcap_t *handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        printf("couldnt open device\n");
        printf("%s\n", errbuf);
    }

    //set the filter on the pcap sniffer
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    //capture packets 
    pcap_loop(handle, -1, got_packet, NULL);

    //close the handle
    pcap_close(handle);

    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
//get iphdr of packer
    struct ipheader *ip = (struct ipheader*)(packet+sizeof(struct ether_header));
    //get the icmp header
    struct icmpheader *icmp = (struct icmpheader *)(packet+sizeof(struct ether_header)+sizeof(struct ipheader));

    //check if the packet is an ICMP echo request
    if(icmp->icmp_type != ICMP_ECHO)
    {
        printf("not an ECHO request\n");
        return;
    }
    printf("this ICMP ECHO request\n");

    //set type to 0- meaning the dest was unreachable 
    icmp->icmp_type = ICMP_ECHOREPLY;
    //get the checksum updated 
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
    
    //switch ip of source and dest
    struct in_addr temp = ip->iph_sourceip;
    ip->iph_sourceip = ip->iph_destip;
    ip->iph_destip = temp;

    ip->iph_ident = 0;
    ip->iph_flag = 0;
    ip->iph_ttl = 24;

    //send the spoofed packet
    printf("src ip: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("dest ip: %s\n", inet_ntoa(ip->iph_destip));
    send_raw_ip_packet(ip);
}

