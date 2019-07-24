#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>

#define PORT 5052

int receive(char *data, char *client_addr, int *size);
int receive_file(char *filename);
