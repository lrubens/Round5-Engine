gcc -fPIC -c ../meths/*.c ../ossl/*.c ../keypair.c ../round5_engine.c -Wall -DR5ND_5PKE_5d -lcrypto -lkeccak -lm -g -lssl
gcc -shared -o round5_engine.so *.o -lcrypto -g -Xlinker -zmuldefs
sudo cp round5_engine.so /usr/local/ssl/lib/engines-1.1/round5.so
