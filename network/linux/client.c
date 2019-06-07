// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include "client.h"
   
int client(){
    struct sockaddr_in address;
	//valread takes a message, sock refers to the socket
    int sock = 0, valread; 
    struct sockaddr_in serv_addr;  
    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    memset(&serv_addr, '0', sizeof(serv_addr)); 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)  
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
	char *message="Hello again from Rubens";
    send(sock , message , strlen(message) , 0 ); 
    printf("Message sent\n");
	//Receive encrypted message
    valread = read( sock , buffer, 1024);
	//Print encrypted message (optional)
    printf("Encrypted message: %s\n",buffer ); 
	//enter your decryption program here
	
	//print the formula of the cypher after you ahve successfuuly decrypted it
	printf("Print cypher parameters\n");
    return 0;
}

// int main(int argc, char const *argv[]) 
// { 
//     return client();
// } 
