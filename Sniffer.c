#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>


#define BUFFERSIZE 65536

int main ()
{
    //set variables 
    int raw_sock;
    char buffer [BUFFERSIZE];
    struct sockaddr_in source, dest; 

    //create raw socket to sniff 
    raw_sock = socket(AF_INET)

    return 0;
}