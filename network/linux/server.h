#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>

#define PORT 5051

int receive(char *data, char *client_addr, int (*handle_request)(char *, char *));
