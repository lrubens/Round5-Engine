// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include "client.h"
   
int send_data(char *address, char *data){
	//valread takes a message, sock refers to the socket
    int sock = 0, valread; 
    struct sockaddr_in serv_addr;  
    char buffer[4096] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    memset(&serv_addr, '0', sizeof(serv_addr)); 
   
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
	//Place your message in this pointer
    
	// char *message="Hello again from Rubens";
    send(sock , data , strlen(data) , 0 ); 
    printf("Message sent\n");
	//Receive encrypted message
    // valread = read( sock , buffer, 4096);
	// //Print encrypted message (optional)
    // printf("Encrypted message: %s\n",buffer ); 
    return 0;
}
