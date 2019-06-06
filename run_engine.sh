gcc engine_check.c -o engine_check -lcrypto -I /home/gfleming/Post-Quantum-PKI/dilithium/ref/ -I reference/src -DR5ND_5PKE_0d install/*.o -lkeccak -lm -Xlinker -zmuldefs -ggdb3 -Wall
valgrind --tool=memcheck --leak-check=full --track-origins=yes ./engine_check
#--show-leak-kinds=all