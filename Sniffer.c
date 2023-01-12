#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

#define BUFFERSIZE 512

 void packetHandler(unsigned char* buffer, int length, FILE *file);
 void print_ip_header(unsigned char *buffer, int length, FILE *file);
 void print_tcp_packet(unsigned char *buffer, int length, FILE *file);



int main ()
{
    //set variables 
    int raw_sock;
    char buffer [BUFFERSIZE];
    struct sockaddr source;
    struct packet_mreq mr;
    int source_size;
    FILE *file;


    //zeroing the source 
    source_size = sizeof(source);
    memset(&source, 0, source_size); 
    

    //create raw socket to sniff 
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(raw_sock<0)
    {
        printf("error in creating socket\n");
        return 1;
    }
    printf("[+]created raw socket\n");

    //turn on the promiscuous mode
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(raw_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    //create the log file
    file = fopen("log.txt", "w");
    if(file == NULL)
    {
        perror("error opening file");
        return 1;
    }
    printf("[+]created log file\n");

    //sniffing packets 
    printf("[+]sniffing packets\n");
    while(1)
    {
        int data_size = recvfrom(raw_sock, buffer, BUFFERSIZE, 0, &source, (socklen_t*)&source_size);
        if(data_size<0)
        {
            printf("failed to get packets\n");
            return 1;
        }
        packetHandler(buffer, data_size, file);
    }

    return 0;
}

 void packetHandler(unsigned char* buffer, int size, FILE *file)
{
    //get the IP header of the packet
    struct iphdr *iph = (struct iphdr*)(buffer+sizeof(struct ethhdr));

    switch(iph->protocol)
    {
        case IPPROTO_TCP:
            printf("TCP\n");
            print_tcp_packet(buffer, size, file);
            return;
        
        case IPPROTO_UDP:
            printf("UDP\n");
            return;

        case IPPROTO_ICMP:
            printf("ICMP\n");
            return;

        default:
            printf("others\n");
            return;
    }
}

void print_tcp_packet(unsigned char *buffer, int length, FILE *file)
{
    print_ip_header(buffer, length, file);
    //get the iphdr of the packet
    struct iphdr *iph = (struct iphdr*)(buffer+sizeof(struct ethhdr));

    //get the tcphdr of the packet
    struct tcphdr *tcph = (struct tcphdr*)(buffer +sizeof(struct ethhdr));

    // char ip_src_str[INET_ADDRSTRLEN];
    fprintf(file, "Source port: %u\n", ntohs(tcph->source));
    fprintf(file, "Destination port: %u\n", ntohs(tcph->dest));

}

void print_ip_header(unsigned char *buffer, int length, FILE *file)
{
    //get the iphdr of the packet
    struct iphdr *iph = (struct iphdr*)(buffer+sizeof(struct ethhdr));

    //get IP source of the packet
    char ip_src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), ip_src_str, INET_ADDRSTRLEN);

    //get IP dest of the packet
    char ip_dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->daddr), ip_dest_str, INET_ADDRSTRLEN);

    fprintf(file, "IP source: %s\n", ip_src_str);
    fprintf(file, "IP destination: %s\n", ip_dest_str);
}