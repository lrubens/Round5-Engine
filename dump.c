int signature(){
  OPENSSL_add_all_algorithms_conf();
  ERR_load_crypto_strings();
  ENGINE_load_dynamic();
  ENGINE *round5_engine;
	T(round5_engine = ENGINE_by_id("round5"));
	T(ENGINE_init(round5_engine));
  T(ENGINE_set_default(round5_engine, ENGINE_METHOD_ALL));
	// T(ENGINE_set_default(round5_engine, ENGINE_METHOD_PKEY_METHS));
  // T(ENGINE_set_default(round5_engine, ENGINE_METHOD_PKEY_ASN1_METHS));
  int hash_nid = NID_KECCAK;
  //const EVP_MD *mdtype;
	// EVP_MD *mdtype = EVP_get_digestbyname("Keccak");
	// EVP_MD_CTX *mctx;
	// T(mctx = EVP_MD_CTX_new());
	// T(EVP_DigestInit_ex(mctx, mdtype, round5_engine));
  // printf("\ninit done\n");
	// T(EVP_DigestUpdate(mctx, "hello", 6));
	// unsigned int len;
	// unsigned char md[512 / 8];
	// T(EVP_DigestFinal(mctx, md, &len));
  // printf("\n%d\n", len);
	// EVP_MD_CTX_free(mctx);
  // printf("\n%s\n", md);

  EVP_PKEY *pkey;
  T(pkey = EVP_PKEY_new());
  char * algname = "Round5";
  T(EVP_PKEY_set_type_str(pkey, algname, strlen(algname)));
  EVP_PKEY_CTX *ctx;
  (ctx = EVP_PKEY_CTX_new(pkey, NULL));
  T(EVP_PKEY_keygen_init(ctx));
  // T(EVP_PKEY_CTX_ctrl(ctx, NID_KECCAK, -1, NULL, NULL, NULL));
  EVP_PKEY *priv_key = NULL;
  //priv_key = EVP_PKEY_new();
  int err = EVP_PKEY_keygen(ctx, &priv_key);
  // printf("\tEVP_PKEY_keygen:\n");
  //print_test_result(err);
  // BIO *b = NULL;
  // b = BIO_new(BIO_s_mem());
  // ASN1_PCTX *pctx = NULL;
  // pctx = ASN1_PCTX_new();
  // unsigned char *private_key_text = NULL;
  // private_key_text = malloc(2048);
  // EVP_PKEY_print_public(b, priv_key, 4, pctx);
  // BIO_get_mem_data(b, &private_key_text);
  // printf("%s\n", private_key_text);
  // BIO_free(b);
  // ASN1_PCTX_free(pctx);
  //EVP_PKEY_set1_engine(pkey, round5_engine);
  // EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  if (err != 1){
    printf("\nerror in keygen\n");
    ENGINE_finish(round5_engine);
    ENGINE_free(round5_engine);
    ENGINE_cleanup();
	  return -1;
  }

  /* Create another key using string interface. */
  EVP_PKEY *key1;
  T(key1 = EVP_PKEY_new());
  T(EVP_PKEY_set_type_str(key1, algname, strlen(algname)));
  EVP_PKEY_CTX *ctx1;
  T(ctx1 = EVP_PKEY_CTX_new(key1, NULL));
  T(EVP_PKEY_keygen_init(ctx1));
  T(EVP_PKEY_CTX_ctrl_str(ctx1, "paramset", NULL));
  EVP_PKEY *key2 = NULL;
  err = EVP_PKEY_keygen(ctx1, &key2);
  // printf("\tEVP_PKEY_*_str:\t\t");
  //print_test_result(err);

  BIO *b = NULL;
  b = BIO_new(BIO_s_mem());
  ASN1_PCTX *pctx = NULL;
  pctx = ASN1_PCTX_new();
  unsigned char *private_key_text = NULL;
  private_key_text = malloc(2048);
  EVP_PKEY_print_public(b, priv_key, 4, pctx);
  BIO_get_mem_data(b, &private_key_text);
  printf("%s\n", private_key_text);
  //BIO_free(b);
  ASN1_PCTX_free(pctx);

  unsigned char msg[] = "hello world";
  unsigned char *hash = NULL;
  hash = malloc(SHA256_DIGEST_LENGTH);
  size_t siglen = 1525 + strlen(msg);//2701 + strlen(hash);
  printf("\nsiglen: %d\n", siglen);
  unsigned char *sig;
  T(sig = OPENSSL_malloc(siglen));
  EVP_PKEY_CTX *cont = EVP_PKEY_CTX_new(priv_key, NULL);
  SHA256(msg, strlen(msg), hash);
  printf("\nhash: %d\n", strlen(hash));
  T(EVP_PKEY_sign_init(cont));
  err = EVP_PKEY_sign(cont, sig, &siglen, hash, 32);
  printf("\nsig2: %s\n", sig);
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 1;
}