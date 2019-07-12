// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include "client.h"
#include <unistd.h>
   
int send_data(char *address, char *data){
	//valread takes a message, sock refers to the socket
    printf("\nData sent: %s\n", data);
    int sock = 0, valread; 
    struct sockaddr_in serv_addr;  
    char buffer[8192] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    memset(&serv_addr, '0', sizeof(serv_addr)); 
    printf("\n%s\n", address);
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, address, &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    }
    char *csr_fields[] = {"name", "country", "province", "city", "organization", "fqdn"};
    char *csr[7] = {0};

    int i;
    for(i = 0; i < sizeof(csr_fields); i++){
        printf("Enter %s:", csr_fields[i]);
        scanf("%s", csr[i]);
    }
    csr[7] = data;
    write(sock, csr, sizeof(csr));
    // send(sock , data , strlen(data) , 0 ); 
    printf("Message sent\n");
    return 0;
}
