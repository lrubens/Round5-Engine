# while :
# do
#   echo Enter Parameter set to use for Round5:
#   read param
#   cmake . -DPARAM=$param
#   echo Selected param: $param
#   make cd Po
#   sudo cp round5.so /usr/local/ssl/lib/engines-1.1/
#   ./engine_check
#   sleep 1
# done
# declare -a params

#!/bin/bash

for param in R5ND_1PKE_5d R5ND_3PKE_5d R5ND_5PKE_5d R5ND_1PKE_0d R5ND_3PKE_0d R5ND_5PKE_0d R5ND_1KEM_5d R5ND_3KEM_5d R5ND_5KEM_5d R5N1_3PKE_0smallCT; do
    cmake . -DPARAM=$param
    # echo Selected param: $param
    make 
    sudo cp round5.so /usr/local/ssl/lib/engines-1.1/
    ./engine_check
    sleep 1 
done


