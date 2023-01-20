#include "interface.h"

FILE *file;


int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
 

    //create the log file
    file = fopen("log.txt", "w");
    if(file == NULL)
    {
        perror("error opening file");
        return 1;
    }
    printf("[+]created log file\n");

    //open live pcap session on NIC with the name eth3
    pcap_t *handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
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
    struct iphdr *ip = (struct iphdr*)(packet+sizeof(struct ether_header));
    //get the tcp header
    struct tcphdr *tcp = (struct tcphdr*)(packet+sizeof(struct ether_header)+ sizeof(struct iphdr));
    //get the app header
    struct apphdr *app = (struct apphdr*)(packet+sizeof(struct ether_header)+ sizeof(struct iphdr)+sizeof(struct tcphdr));
    //get the data pointer
    char *data =(char*)(packet+sizeof(struct ether_header)+ sizeof(struct iphdr)+sizeof(struct tcphdr)+sizeof(struct apphdr));
    
   
    static int packet_num = 0; 
    //write the number of packet
    packet_num ++;
    fprintf(file, "------packet #%d------\n", packet_num);

 

    //get IP source of the packet
    char ip_src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), ip_src_str, INET_ADDRSTRLEN);

    //get IP dest of the packet
    char ip_dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), ip_dest_str, INET_ADDRSTRLEN);

    fprintf(file, "IP source: %s\n", ip_src_str);
    fprintf(file, "IP destination: %s\n", ip_dest_str);

    // char ip_src_str[INET_ADDRSTRLEN];
    fprintf(file, "Source port: %u\n", ntohs(tcp->source));
    fprintf(file, "Destination port: %u\n", ntohs(tcp->dest));

     //retrieve the status code of the packet and write to file
    fprintf(file, "status code: %u\n", app->status);

    //write size of packet to the file 
    fprintf(file, "length: %u\n", header->caplen);

    // get cache flag and write it to the file 
    fprintf(file, "cache flag: %u\n", app->c_flags);

    //get steps flag and write it to file 
    fprintf(file, "steps flag: %u\n", app->s_flag);

    //get type flag and write it to file 
    fprintf(file, "type flag: %u\n", app->t_flag);

    //get cache control and write it to the file
    fprintf(file, "cache control: %u\n", app->cache);


    //convert data to hex and write it to file
    if(tcp->psh)
    {
 
         fprintf(file, "data:");
        for (int i=0; i<header->len; i++)
        {
            if(!(i&15)) fprintf(file, "\n%04X: ", i);
            fprintf(file, "%02X ", ((unsigned char*)packet)[i]);
        }
    }
    fprintf(file, "\n");
}

