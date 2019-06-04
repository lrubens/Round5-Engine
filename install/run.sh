gcc -fPIC -I /home/gfleming/Post-Quantum-PKI/meths/ -I /home/gfleming/XKCP/bin/generic64/libkeccak.a.headers/ -I /home/gfleming/Post-Quantum-PKI/dilithium/ref/ -c /home/gfleming/Post-Quantum-PKI/dilithium/ref/sign.c ../meths/*.c ../ossl/*.c ../keypair.c ../round5_engine.c -Wall -DR5ND_5PKE_5d -lcrypto -lkeccak -lm -g -lssl
gcc -shared -o round5_engine.so *.o -lcrypto -g -Xlinker -zmuldefs
