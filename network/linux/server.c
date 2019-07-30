#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "server.h"
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include "../../keypair.h"

#define BUFFER_SIZE 8192


char *strip(char *str, const char *sub) {
    char *p, *q, *r;
    if ((q = r = strstr(str, sub)) != NULL) {
        size_t len = strlen(sub);
        while ((r = strstr(p = r + len, sub)) != NULL) {
            memmove(q, p, r - p);
            q += r - p;
        }
        memmove(q, p, strlen(p) + 1);
    }
    return str;
}

char *strnstr(const char *s, const char *find, size_t slen){
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if (slen-- < 1 || (sc = *s++) == '\0')
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

// void sig_handler(int buf){
// 	close(sockfd);
// 	close(newSocket);
// }

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);
	// int decodeLen = *length;
	printf("\nsize in decode: %d\n", decodeLen);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));
	assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);
	printf("\ndecoded buffer: %s\n", buffer);
	return (0); //success
}



int receive(char *data, char *client_addr, int *size){
	// signal(SIGINT, sig_handler);
	int sockfd, newSocket;
	int ret;
	struct sockaddr_in serverAddr;

	// int newSocket;
	struct sockaddr_in newAddr;

	socklen_t addr_size;

	char buffer[BUFFER_SIZE];
	pid_t childpid;
    
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		printf("[-]Error in connection.\n");
		exit(1);
	}
	int one = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &one, sizeof(one)) == -1){
		perror("setsockopt");
		exit(1);
	}
	printf("[+]Server Socket is created.\n");

	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	memset(&(serverAddr.sin_zero), 0, 8); // zero the rest of the struct
    
	ret = bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	if(ret < 0){
		printf("[-]Error in binding.\n");
		exit(1);
	}

	if(listen(sockfd, 10) == 0){
		printf("[+]Listening....\n");
	}else{
		printf("[-]Error in binding.\n");
	}

	while(1){
		addr_size = sizeof(struct sockaddr_in);
		newSocket = accept(sockfd, (struct sockaddr*)&newAddr, &addr_size);
		struct sockaddr_in *addr = (struct sockaddr_in *)&newAddr;
        struct in_addr ip_addr = addr->sin_addr;
        inet_ntop(AF_INET, &ip_addr, client_addr, INET_ADDRSTRLEN);
		if(newSocket < 0){
			printf("return: %d", newSocket);
            printf("Accept failed");
			exit(1);
		}
		printf("Connection accepted from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
		int count = 1;
		char *buf = malloc(BUFFER_SIZE);
		int msg_len = BUFFER_SIZE;
		// char *size_buf = malloc(sizeof(int));
		int32_t data_size;
		recv(newSocket, &data_size, sizeof(data_size), 0);
		printf("\nsize: %d\n", data_size);
		while(1){
			char *recv_buf = malloc(BUFFER_SIZE);
			printf("Preparing to receive\n");
			recv(newSocket, recv_buf, BUFFER_SIZE, 0);
			// printf("\n\n\n\nawiofhaweofijweowefwewafe\n\n\n");
			// print_hex("data in receive", data, 1541, 1);
			// printf("\nBuf2: %s\n", recv_buf);
			if(strnstr(recv_buf, ":exit", BUFFER_SIZE) != NULL){
				if(count == 1){
					memcpy(buf, recv_buf, BUFFER_SIZE);
				}
				else{
					strncat(buf, recv_buf, BUFFER_SIZE);
				}
				printf("Disconnected from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
				// printf("\nBuf2: %s\n", recv_buf);
				break;
			}
			else{
				if(msg_len > 8192){
					char *temp = realloc(buf, count * BUFFER_SIZE);
					buf = temp;
				}
				strncat(buf, recv_buf, BUFFER_SIZE);
				count++;
				msg_len += BUFFER_SIZE;
			}
		}
		buf = strip(buf, ":exit");
		printf("\nBuf: %s\n", buf);
		// char *decoded_data;
		// size_t decoded_size;
		// // Base64Decode(buf, &decoded_data, &data_size);
		// decoded_data = unbase64(buf, data_size);
		// printf("\nReceived: %s\n", decoded_data);
		char *ACK = "Received message";
		send(newSocket, ACK, strlen(ACK), 0);
		// int i = 0;
		// char *data = strtok(buf, "-SEP-");
		// char *buf_arr[2] = {NULL};
		// while(buf != NULL){
		//   buf_arr[i++] = buf;
		//   buf = strtok(NULL, "-SEP-");
		// }
		// printf("\n%s\n%s\n", buf_arr[0], buf_arr[1]);
		// int data_size = atoi(buf_arr[1]);
		memcpy(data, buf, data_size);
		*size = data_size;
		// BIO *b = NULL;
    	// b = BIO_new_mem_buf(buf, strlen(buf));
		// EVP_PKEY *client_key = NULL;
		// client_key = PEM_read_bio_PUBKEY(b, &client_key, NULL, NULL);
		// if(!client_key){
		// ps("client key is null");
		// }
		// struct ROUND5 *kpair = EVP_PKEY_get0(client_key);
		// print_hex("data in receive", data, 1541, 1);
		close(sockfd);
		close(newSocket);
		break;
	}
	// 	if((childpid = fork()) == 0){
	// 		close(sockfd);
    //         int count = 1;
    //         char *buf = NULL;
	// 		while(1){
    //             char *recv_buf = malloc(BUFFER_SIZE);
	// 			recv(newSocket, recv_buf, BUFFER_SIZE, 0);
	// 			printf("\nrecv_buf: %s\n", recv_buf);
	// 			if(strstr(recv_buf, ":exit") != NULL){
	// 				buf = recv_buf;
	// 				printf("Disconnected from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));
    //                 // printf("\nBuf2: %s\n", recv_buf);
	// 				break;
	// 			}
    //             else{
	// 				char *temp = realloc(buf, count * BUFFER_SIZE);
    //                 buf = temp;
    //                 strcat(buf, recv_buf);
	// 				count++;
    //                 // count++;
    //                 // char *temp = realloc(buf, count * BUFFER_SIZE);
    //                 // buf = temp;
    //                 // strcat(buf, buffer);
    //             }
	// 		}
	// 		printf("\nBuf before strip: %s\n", buf);
	// 		buf = strip(buf, ":exit");
    //         printf("\nBuf: %s\n", buf);
	// 		printf("\n\n\n\n");
	// 		// printf("Press 1 to keep receiving ")
    //         if(handle_request){
    //             handle_request(buffer);
    //         }
	// 		close(newSocket);
	// 		exit(0);
	// 	}
    //     break;

	// }
	
	return 0;
}

int receive_file(char *filename){
	int server_socket;
    int peer_socket;
    socklen_t       sock_len;
    ssize_t len;
    struct sockaddr_in      server_addr;
    struct sockaddr_in      peer_addr;
    int fd;
    int sent_bytes = 0;
    int file_size;
    int offset;
    int remain_data;

    /* Create server socket */
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
            fprintf(stderr, "Error creating socket");

            exit(EXIT_FAILURE);
    }
	int one = 1;
	if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &one, sizeof(one)) == -1){
		perror("setsockopt");
		exit(1);
	}

    /* Zeroing server_addr struct */
    memset(&server_addr, 0, sizeof(server_addr));
    /* Construct server_addr struct */
    server_addr.sin_family = AF_INET;
    // inet_pton(AF_INET, server, &(server_addr.sin_addr));
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    /* Bind */
    if ((bind(server_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr))) == -1)
    {
            fprintf(stderr, "Error on bind");

            exit(EXIT_FAILURE);
    }

    /* Listening to incoming connections */
    if ((listen(server_socket, 5)) == -1)
    {
            fprintf(stderr, "Error on listen");

            exit(EXIT_FAILURE);
    }
    sock_len = sizeof(struct sockaddr_in);
    /* Accepting incoming peers */
    peer_socket = accept(server_socket, (struct sockaddr *)&peer_addr, &sock_len);
    if (peer_socket == -1)
    {
            fprintf(stderr, "Error on accept");

            exit(EXIT_FAILURE);
    }
    fprintf(stdout, "Accept peer --> %s\n", inet_ntoa(peer_addr.sin_addr));
    char buffer[2048];
    recv(peer_socket, buffer, 5, 0);
    file_size = atoi(buffer);
	printf("\nFile size: %d", file_size);
    FILE *received_file = fopen(filename, "w");
	if(received_file == NULL){
		printf("File failed to open");
		exit(0);
	}
    // fprintf(stdout, "Client sent %d bytes for the size\n", len);
	memset(buffer, 0, 2048);
	// printf("\nFile content: %s\n", buffer);
    offset = 0;
    remain_data = file_size;
    while ((remain_data > 0) && ((len = recv(peer_socket, buffer, BUFFER_SIZE, 0)) > 0)){
            fwrite(buffer, sizeof(char), len, received_file);
            remain_data -= len;
            fprintf(stdout, "Receive %d bytes and we hope :- %d bytes\n", len, remain_data);
    }
    fclose(received_file);
    close(peer_socket);
    close(server_socket);

    return 0;
}

// #include <unistd.h> 
// #include <stdio.h> 
// #include <sys/socket.h> 
// #include <stdlib.h> 
// #include <netinet/in.h> 
// #include <string.h>
// #include "server.h"
// #include <arpa/inet.h>

// int receive(char *data, char *client, int (*handle_request)(char *, char *)){
//     char *client_addr;
//     int size = 8192;
//     // data = malloc(size);
//     int server_fd, new_socket, valread; 
//     struct sockaddr_in address;
//     int opt = 1; 
//     int addrlen = sizeof(address); 
//     char buffer[size];
//     while(1) {
//         // memset (data, 0, size*sizeof(char));
//         // puts(data);

//         // Creating socket file descriptor 
//         if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
//         {
//                 perror("socket failed"); 
//                 exit(EXIT_FAILURE); 
//         } 

//         // Forcefully attaching socket to the port 8080 
//         if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
//                                 &opt, sizeof(opt))) 
//         { 
//                 perror("setsockopt"); 
//                 exit(EXIT_FAILURE);
//         } 
//         address.sin_family = AF_INET; 
//         address.sin_addr.s_addr = INADDR_ANY; 
//         address.sin_port = htons( PORT ); 

//         // Forcefully attaching socket to the port 5050 
//         if (bind(server_fd, (struct sockaddr *)&address, 
//                                 sizeof(address))<0) 

//         { 
//                 perror("bind failed"); 
//                 exit(EXIT_FAILURE); 
//         } 
//         if (listen(server_fd, 3) < 0) 
//         { 
//                 perror("listen"); 
//                 exit(EXIT_FAILURE); 

//         } 
//         if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
//                                         (socklen_t*)&addrlen))<0) 
//         { 
//                 perror("accept"); 
//                 exit(EXIT_FAILURE); 
//         }
//         struct sockaddr_in *addr = (struct sockaddr_in *)&address;
//         struct in_addr ip_addr = addr->sin_addr;
//         client_addr = malloc(INET_ADDRSTRLEN);
//         inet_ntop(AF_INET, &ip_addr, client, INET_ADDRSTRLEN);
//         // char *data_[7] = {0};
//         // char data_[7][30];
//         // char **data_ = malloc(7 * sizeof(*data_));
        
//         valread = recv( new_socket , buffer, 8192, 0); 
//         // char *buf = malloc(8192);
//         printf("\nbuffer_len: %d\n", strlen(buffer));
//         if(!data)
//             data = malloc(strlen(buffer) + 1);
//         printf("\nbuffer: %s\n", buffer);
//         strcpy(data, buffer);
//         // printf("\ndata: %s\n", data);
//         // int count = 0;
//         // char *client_req[7];
//         // char *data_ = strtok(buf, "/");
//         // while(data_ != NULL){
//         //     client_req[count++] = data_;
//         //     // printf("\ndata_: %s\n", data_);
//         //     data_ = strtok(NULL, "/");
//         // }
//         // strcpy(data, client_req[6]);
//         // if((*handle_request)){
//         // //     printf("done");
//         //     (*handle_request)(data, client_addr);
//         // }
//         // printf("\nIP Address: %s\n", client_addr);
//         // printf("\n%s\n", data);
//         close(new_socket);
//         break;
//     }
//     return 1; 
// }