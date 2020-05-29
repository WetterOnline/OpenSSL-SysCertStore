#ifndef SYSCERTSTORE_H
#define SYSCERTSTORE_H

#include <openssl/ssl.h>

/**
 * Loads the system-wide installed CA certificates into an OpenSSL X509 certificate store.
 * @param certStore		An OpenSSL certificate store, possibly obtained by SSL_CTX_get_cert_store from an SSL_CTX
 * @return				0 on success, 1 on error
 */
int loadSysCertStore (X509_STORE* certStore);

#endif

