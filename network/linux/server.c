#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h>
#include "server.h"
#include <arpa/inet.h>

int receive(void *data, int (*handle_request)(char *, char *)){
    char *client_addr;
    int size = 8192;
    data = malloc(size);
    int server_fd, new_socket, valread; 
    struct sockaddr_in address;
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[size];
    while(1) {
        memset (data, 0, size*sizeof(char));
        // puts(data);

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
        // char *data_[7] = {0};
        // char data_[7][30];
        // char **data_ = malloc(7 * sizeof(*data_));
        
        valread = recv( new_socket , data, 8192, 0); 
        char *data_ = strtok(data, "\n");
        while(data_ != NULL){
            printf("\ndata_: %s\n", data_);
            data_ = strtok(NULL, "\n");
        }
        int i;
        // char *pk;
        // for(i = 0; i < strlen(data); i++){
        //     if(data[i] == "\n"){
        //         pk = malloc(strlen(data) - i);
        //         strncpy(pk, data + i + 1, strlen(data) - i);
        //     }
        // }
        // printf("\nPK!!!!!!!: %s\n", pk);

        // printf("\n%s\n", data_[1]);
        // data = data_[1];
        // printf("\n%s\n", data);
        // revc_size(new_socket, &data)
        if((*handle_request)){
            printf("done");
            (*handle_request)(data, client_addr);
        }
        printf("\nIP Address: %s\n", client_addr);
        printf("\n%s\n", data);
        
        break;
    }
    return 1; 
}
