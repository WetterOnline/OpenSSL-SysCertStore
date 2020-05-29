OpenSSL-SysCertStore is a small C library for loading system-wide installed CA certificates and using them in the OpenSSL library on Windows, Mac OS, and Linux. This allows applications that use OpenSSL in client mode to verify the server's identity without having to maintain their own certificate repository. This is particularly useful for applications that just need to consume some REST API and can also be used in conjunction with Boost.Asio's SSL support.

## How it works
On Windows, the library uses the Wincrypt API to obtain the system certificate store. On Mac OS, it uses the system root keychain via the Security framework. On Linux, it checks some commonly-used directories and files for preinstalled certificates. This approach is not recommended for applications with high security demands, as it automatically trusts any installed certificate.

## How to use
Compile the `syscertstore.c` file as part of your project and `#include` the `syscertstore.h` in your source code. After creating an `SSL_CTX` instance, load the system certificates like this:
```c
SSL_CTX *ctx = SSL_CTX_new (SSLv23_client_method ());
loadSysCertStore (SSL_CTX_get_cert_store (ctx));
```
Certificates are now available for usage by host verification. Link the application with `-lssl -lcrypto`. On Windows, additionally link with `-lcrypt32`. On Mac OS, additionally link with `-framework Security -framework Foundation`.

## Credits
Pieced together with information from StackOverflow [1](https://stackoverflow.com/a/40046425), [2](https://stackoverflow.com/q/33947623) and [3](https://serverfault.com/a/722646).

## License
This project is available under the MIT license.
