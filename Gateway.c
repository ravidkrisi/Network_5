#include "interface.h"

int main (int argc, char *argv[])
{
    //set variables 
    char buffer[BUFFERSIZE] = {'0'};
    int recv_sock = -1, send_sock=-1, port = -1, client_size, bytes_recv;
    struct sockaddr_in recv_add;
    struct sockaddr_in send_add;
    struct sockaddr_in client_add;


    //intalize the port from the user 
    port = atoi(argv[1]);

    //set receive address 
    recv_add.sin_family = AF_INET;
    recv_add.sin_addr.s_addr = INADDR_ANY;
    recv_add.sin_port = htons(port);

    //set send address
    recv_add.sin_family = AF_INET;
    recv_add.sin_addr.s_addr = INADDR_ANY;
    recv_add.sin_port = htons(port+1);


    //create receive and send  DATAGRAM sockets 
    if((send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        perror("failed to create send socket\n");
        return -1;
    }

    if((recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        perror("failed to create receieve socket\n");
        return -1;
    }

    //bind the recieve socket 
    if(bind(recv_sock, (struct sockaddr*)&recv_add, sizeof(recv_add)) == -1)
    {
        perror("binding receive socket failed \n");
        return -1;
    }

    //bind the recieve socket 
    if(bind(recv_sock, (struct sockaddr*)&send_add, sizeof(send_add)) == -1)
    {
        perror("binding receive socket failed \n");
        return -1;
    }

    while(1)
    {
        memset((char *)&client_add, 0, sizeof(client_add));
        memset(buffer, '0', sizeof(buffer));
        client_size = sizeof(client_add);
        bytes_recv = -1;
        
        bytes_recv = recvfrom(recv_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_add, &client_size);
        if(bytes_recv == -1)
        {
            printf("recevie from client failed\n");
        }
        else
        {
            if((((float)random())/((float)RAND_MAX))>0.5)
            {
                if(sendto(send_sock, buffer, bytes_recv, 0, (struct sockaddr *)&client_add, client_size) == -1)
                {
                    printf("error sending to client\n");
                }
            }
        }

    }

    //closing sockets
    close(recv_sock);
    close(send_sock);

}