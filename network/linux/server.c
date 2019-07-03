#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h>
#include "server.h"

int receive(char *data, char *client_addr){
    int server_fd, new_socket, valread; 
    struct sockaddr_in address;
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[4096];
    while(1) {
        memset (data, 0, 4096*sizeof(char));
        puts(data);

        // Creating socket file descriptor 
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
        { 
                perror("socket failed"); 
                exit(EXIT_FAILURE); 
        } 

        // Forcefully attaching socket to the port 8080 
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                &opt, sizeof(opt))) 
        { 
                perror("setsockopt"); 
                exit(EXIT_FAILURE);
        } 
        address.sin_family = AF_INET; 
        address.sin_addr.s_addr = INADDR_ANY; 
        address.sin_port = htons( PORT ); 

        // Forcefully attaching socket to the port 5050 
        if (bind(server_fd, (struct sockaddr *)&address, 
                                sizeof(address))<0) 

        { 
                perror("bind failed"); 
                exit(EXIT_FAILURE); 
        } 
        if (listen(server_fd, 3) < 0) 
        { 
                perror("listen"); 
                exit(EXIT_FAILURE); 

        } 
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                                        (socklen_t*)&addrlen))<0) 
        { 
                perror("accept"); 
                exit(EXIT_FAILURE); 
        } 
        struct sockaddr_in *addr = (struct sockaddr_in *)&address;
        struct in_addr ip_addr = addr->sin_addr;
        client_addr = malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_addr, client_addr, INET_ADDRSTRLEN);
        valread = read( new_socket , data, 4096); 
        printf("%s\n",data);
    }
    return 1; 
}