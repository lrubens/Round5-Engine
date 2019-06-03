gcc -fPIC -I /home/gfleming/Post-Quantum-PKI/meths/ -I /home/gfleming/XKCP/bin/generic64/libkeccak.a.headers/ -c ../meths/*.c ../ossl/*.c ../keypair.c ../round5_engine.c -Wall -DR5ND_5PKE_5d -lcrypto -lkeccak -lm -g -lssl
gcc -shared -o round5_engine.so *.o -lcrypto -g -Xlinker -zmuldefs
