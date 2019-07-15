// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include "client.h"
#include <unistd.h>

void raw_input(char *prompt, char *buffer, size_t length){
    printf("%s", prompt);
    fflush(stdout);
    // fgets(buffer, length, stdin);
    scanf("%s", buffer);
}
   
int send_data(char *address, void *data, int to_server){
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
    // char **csr = malloc(7 * sizeof(*csr));
    // *csr = "Rubens";
    // *(csr+1) = "US";
    // *(csr+2) = "MA";
    // *(csr+3) = "Cambridge";
    // *(csr+4) = "Draper";
    // *(csr+5) = "hostname";
    // *(csr+6) = data;
    char *csr[] = {"Rubens", "US", "MA", "Cambridge", "Draper", "hostname", data};
    char str[8192];
    if(to_server){
        sprintf(str, "%s/%s/%s/%s/%s/%s/%s", csr[0], csr[1], csr[2], csr[3], csr[4], csr[5], csr[6]);
    }
    else{
        sprintf(str, "%s", data);
    }
    printf("\nstr: %s\n", str);
    // csr = {"Rubens", "US", "MA", "Cambridge", "Draper", "hostname", data};
    // for(i = 0; i < sizeof(*csr_fields); i++){
    //     raw_input(("Enter %s:", csr_fields[i]), csr[i], 1024);
    // }
    send(sock , str, strlen(str), 0);
    close(sock);
    // send(sock, data, data_len, 0); 
    printf("Message sent\n");
    return 0;
}
