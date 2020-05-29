#include <stddef.h>
#include "syscertstore.h"

#if defined (_WIN32) || defined (_WIN64)

#include <windows.h>
#include <wincrypt.h>

int loadSysCertStore (X509_STORE* certStore) {
	HCERTSTORE hStore;
	PCCERT_CONTEXT pContext;
	const unsigned char *encoded_cert;
	
	hStore = CertOpenSystemStoreW (0, L"ROOT");

	if (!hStore)
		return 1;

	while (1) {
		pContext = CertEnumCertificatesInStore (hStore, pContext);
		if (pContext == NULL)
			break;
		
		encoded_cert = pContext->pbCertEncoded;
		X509* x509 = d2i_X509 (NULL, &encoded_cert, pContext->cbCertEncoded);
		if (x509) {
			X509_STORE_add_cert (certStore, x509);

			X509_free (x509);
		}
	}

	CertFreeCertificateContext (pContext);
	CertCloseStore (hStore, 0);
	return 0;
}

#endif

#if defined (__APPLE__)

#include <Security/SecImportExport.h>
#include <Security/SecItem.h>
#include <Security/SecCertificate.h>

int loadSysCertStore (X509_STORE* certStore) {
	SecKeychainRef systemRoots = NULL;
	OSStatus kcStatus;
	CFArrayRef currentSearchList;
	CFMutableArrayRef newSearchList;
	CFMutableDictionaryRef attrDict;
	CFIndex certCount;
	SecCertificateRef cert;
	CFDataRef derCert;
	const unsigned char *encoded_cert;
	CFIndex length;
	X509* x509;
	int ret = 1;
	CFIndex i;
	
	kcStatus = SecKeychainOpen ("/System/Library/Keychains/SystemRootCertificates.keychain", &systemRoots);

	if (SecKeychainCopySearchList (&currentSearchList) != errSecSuccess)
		return 1;

	newSearchList = CFArrayCreateMutableCopy (NULL, CFArrayGetCount(currentSearchList) + 1, currentSearchList);

	if (kcStatus == errSecSuccess) {
		/* Use system root certificate keychain if available */
		CFArrayAppendValue (newSearchList, systemRoots);
	}

	attrDict = CFDictionaryCreateMutable (NULL, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (attrDict == NULL)
		goto FreeLists;

	CFDictionaryAddValue (attrDict, kSecMatchSearchList, newSearchList);
	CFDictionaryAddValue (attrDict, kSecClass, kSecClassCertificate);
	CFDictionaryAddValue (attrDict, kSecReturnRef, kCFBooleanTrue);
	CFDictionaryAddValue (attrDict, kSecMatchLimit, kSecMatchLimitAll);
	CFDictionaryAddValue (attrDict, kSecMatchTrustedOnly, kCFBooleanFalse);

	CFArrayRef certArray;
	if (SecItemCopyMatching (attrDict, (CFTypeRef*) (&certArray)) != errSecSuccess)
		goto FreeDict;

	certCount = CFArrayGetCount (certArray);
	for (i = 0; i < certCount; ++i) {
		cert = (SecCertificateRef) CFArrayGetValueAtIndex (certArray, i);

		derCert = SecCertificateCopyData (cert);
		if (derCert != NULL) {
			encoded_cert = CFDataGetBytePtr (derCert);
			length = CFDataGetLength (derCert);
			x509 = d2i_X509 (NULL, &encoded_cert, length);
			if (x509) {
				X509_STORE_add_cert (certStore, x509);

				X509_free (x509);
			}
			CFRelease (derCert);
		}
	}
	
	ret = 0;
	
	CFRelease (certArray);
	
	FreeDict:
		CFRelease (attrDict);
	
	FreeLists:
		CFRelease (newSearchList);
		CFRelease (currentSearchList);

	return ret;
}

#elif defined (__unix__)

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static const char* defaultCAFiles [] = {
	"/etc/ssl/certs",               /* SLES10/SLES11, https://golang.org/issue/12139 */
	"/system/etc/security/cacerts", /* Android */
	"/usr/local/share/certs",       /* FreeBSD */
	"/etc/pki/tls/certs",           /* Fedora/RHEL */
	"/etc/openssl/certs",           /* NetBSD */
	"/var/ssl/certs",               /* AIX */
};

static const char* defaultCADirs [] = {
	"/etc/ssl/certs",               /* SLES10/SLES11, https://golang.org/issue/12139 */
	"/system/etc/security/cacerts", /* Android */
	"/usr/local/share/certs",       /* FreeBSD */
	"/etc/pki/tls/certs",           /* Fedora/RHEL */
	"/etc/openssl/certs",           /* NetBSD */
	"/var/ssl/certs",               /* AIX */
};

int loadSysCertStore (X509_STORE* certStore) {
	X509_LOOKUP *lookup;
	struct stat statbuf;
	size_t i;

	lookup = X509_STORE_add_lookup (certStore, X509_LOOKUP_file ());
	if (lookup != NULL) {
		X509_LOOKUP_load_file (lookup, NULL, X509_FILETYPE_DEFAULT);
		for (i = 0; i < (sizeof(defaultCAFiles)/sizeof(defaultCAFiles[0])); ++i) {
			
			/* Check for regular files */
			if (stat (defaultCAFiles [i], &statbuf) == 0 && S_ISREG(statbuf.st_mode)) {
				X509_LOOKUP_load_file (lookup, defaultCAFiles [i], X509_FILETYPE_PEM);
			}
		}
	}

	lookup = X509_STORE_add_lookup (certStore, X509_LOOKUP_hash_dir());
	if (lookup != NULL) {
		X509_LOOKUP_add_dir (lookup, NULL, X509_FILETYPE_DEFAULT);
		for (i = 0; i < (sizeof(defaultCADirs)/sizeof(defaultCADirs[0])); ++i) {
		
			/* Check for directories */
			if (stat (defaultCADirs [i], &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
				X509_LOOKUP_add_dir (lookup, defaultCADirs [i], X509_FILETYPE_PEM);
			}
		}
	}
	
	return 0;
}

#endif

