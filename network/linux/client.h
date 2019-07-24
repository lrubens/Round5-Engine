#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 

#define PORT 5052

int send_data(char *address, char *data, int32_t size)  ;
int send_encoded_data(char *address, char *data, int32_t size)  ;
int send_raw_data(char *address, char *data, int32_t size, int to_encode);
int send_file(char *filename, char *server);