#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>

#define PORT 5050

int receive(char *data, int (*handle_request)(char *, char *));
