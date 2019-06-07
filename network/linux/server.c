#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h>
#include "server.h"

int server(){
    int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024];
    char hello[]="Hello from server";
    int  iteration = 0;
    while(1) {
        memset (buffer,0,1024*sizeof(char));
        puts(buffer);

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

        // Forcefully attaching socket to the port 8080 
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
        valread = read( new_socket , buffer, 1024); 
        printf("%s\n",buffer ); 
        //decrypt
        int i=0;
        int val;
        while(buffer[i]!=0)
        {
                val=(int)(buffer[i])-97;
                val=val*17+12;
                val=val%26;
                val=val+97;
                buffer[i]=val;
                i++;

        }
        send(new_socket , buffer,i, 0 );
        close(server_fd);
        printf("Hello message sent\n");
    }
    return 0; 
}

// int main(int argc, char const *argv[]) 
// { 
//     return server();
// } 