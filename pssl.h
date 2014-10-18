
  struct ssl_data {
    pk_context key;
    ssl_context ssl;
    x509_crt crt;
    dhm_context dhm;
    struct {
      x509_crt crt;
      pk_context key;
    }* snidata;
  };

extern int init_serverside_tls(struct ssl_data* d,int sock);
extern void free_tls_ctx(struct ssl_data* d);
extern void free_tls_memory(void);
