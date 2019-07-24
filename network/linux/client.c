// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include "client.h"
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "../../keypair.h"

#define BUFFER_SIZE 2048

void raw_input(char *prompt, char *buffer, size_t length){
    printf("%s", prompt);
    fflush(stdout);
    // fgets(buffer, length, stdin);
    scanf("%s", buffer);
}

void clean_str(char *str, char *end){
  char *ptr = strstr(str, end);
  if(!ptr){
    *ptr = '\0';
  }
}

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	// BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=(*bufferPtr).data;

	return (0); //success
}
   
int send_data(char *address, char *data, int32_t size){
	//valread takes a message, sock refers to the socket
    // printf("\nData sent: %s\n", data);
    int sock = 0, valread; 
    struct sockaddr_in serv_addr;  
    char buffer[8192] = {0};
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
    char *csr_fields[] = {"name", "country", "province", "city", "organization", "fqdn"};
    char *csr[] = {"Rubens", "US", "MA", "Cambridge", "Draper", "hostname", data};
    char str[8192] = {NULL};
    // if(to_server){
    //     sprintf(str, "%s/%s/%s/%s/%s/%s/%s", csr[0], csr[1], csr[2], csr[3], csr[4], csr[5], csr[6]);
    // }
    // else{
    //     sprintf(str, "%s", (char *)data);
    // }
    // print_hex("Encrypted_key in main", data, 1541, 1);
    // printf("\nstr in client: %s\n", str);
    char *sig_end = ":exit";
    // printf("\n%d\n", strlen(data));
    // size_t msg_len = strlen((char *)data);
    // printf("\nmsg_len: %d\n", msg_len);
    // clean_str(str, "-----\n");
    send(sock, &size, sizeof(size), 0);
    // char *size_buf = malloc(sizeof(int));
    // char *separator = "-SEP-";
    // sprintf(size_buf, "%d", size);
    // sprintf(str, "%s%s%s", data, separator, size_buf);
    // send(sock , str, size + strlen(separator) + strlen(size_buf), 0);
    // print_hex("Data in send", data, 1541, 1);
    char *encoded_data;
    // Base64Encode(data, size, &encoded_data);
    // encoded_data = base64(data, size);
    send(sock, data, size, 0);
    send(sock, sig_end, strlen(sig_end), 0);
    char *ACK = malloc(17);
    recv(sock, ACK, 17, 0);
    printf("\nReceived: %s\n", ACK);
    close(sock);
    // send(sock, data, data_len, 0); 
    printf("Message sent\n");
    return 0;
}

int send_file(char *filename, char *server){
    int client_socket;
	ssize_t len;
	struct sockaddr_in remote_addr;
	char buffer[BUFSIZ];
	int file_size;
    struct stat file_stat;
	int remain_data = 0;

	/* Zeroing remote_addr struct */
	memset(&remote_addr, 0, sizeof(remote_addr));

	/* Construct remote_addr struct */
	remote_addr.sin_family = AF_INET;
	inet_pton(AF_INET, server, &(remote_addr.sin_addr));
	remote_addr.sin_port = htons(PORT);

	/* Create client socket */
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket == -1)
	{
			fprintf(stderr, "Error creating socket");

			exit(EXIT_FAILURE);
	}

	/* Connect to the server */
	if (connect(client_socket, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr)) == -1)
	{
			fprintf(stderr, "Error on connect");

			exit(EXIT_FAILURE);
	}

	int fd = open(filename, O_RDONLY);
    // printf("fd: %d", fd);
    fstat(fd, &file_stat);
	fprintf(stdout, "File Size: %d bytes\n", file_stat.st_size);
    file_size = file_stat.st_size;
    char *file_size_str = malloc(5);
    sprintf(file_size_str, "%d", file_size);
	len = send(client_socket, file_size_str, sizeof(file_size_str), 0);
    int offset = 0;
    remain_data = file_stat.st_size;
    printf("\n%d", remain_data);
    int sent_bytes;
	while (((sent_bytes = sendfile(client_socket, fd, &offset, 256)) > 0) && (remain_data > 0)){
            fprintf(stdout, "1. Server sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
            remain_data -= sent_bytes;
            fprintf(stdout, "2. Server sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
    }
    printf("\nbytes sent: %d\n", sent_bytes);
	close(client_socket);
	return 0;
}
