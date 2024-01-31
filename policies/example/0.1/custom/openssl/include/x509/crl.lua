local ffi = require "ffi"

require "custom.openssl.include.ossl_typ"
require "custom.openssl.include.evp"
require "custom.openssl.include.objects"
require "custom.openssl.include.x509"
require "custom.openssl.include.stack"

local asn1_macro = require "custom.openssl.include.asn1"

local OPENSSL_10 = require("custom.openssl.version").OPENSSL_10
local OPENSSL_11 = require("custom.openssl.version").OPENSSL_11

asn1_macro.declare_asn1_functions("X509_CRL")

ffi.cdef [[
  X509_NAME *X509_CRL_get_issuer(const X509_CRL *crl);
  int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
  int X509_CRL_set_version(X509_CRL *x, long version);

  int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
  X509_EXTENSION *X509_CRL_get_ext(const X509_CRL *x, int loc);
  int X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos);
  void *X509_CRL_get_ext_d2i(const X509_CRL *x, int nid, int *crit, int *idx);

  int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);
  int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);

  int i2d_X509_CRL_bio(BIO *bp, X509_CRL *crl);
  X509_CRL *d2i_X509_CRL_bio(BIO *bp, X509_CRL **crl);
]]

if OPENSSL_11 then
  ffi.cdef [[
    int X509_CRL_set1_lastUpdate(X509_CRL *x, const ASN1_TIME *tm);
    int X509_CRL_set1_nextUpdate(X509_CRL *x, const ASN1_TIME *tm);
    /*const*/ ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl);
    /*const*/ ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl);
    long X509_CRL_get_version(const X509_CRL *crl);

    X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);
  ]]
elseif OPENSSL_10 then
  -- in openssl 1.0.x some getters are direct accessor to struct members (defiend by macros)
  ffi.cdef [[
    typedef struct X509_crl_info_st {
      ASN1_INTEGER *version;
      /*X509_ALGOR*/ void *sig_alg;
      X509_NAME *issuer;
      ASN1_TIME *lastUpdate;
      ASN1_TIME *nextUpdate;
      // STACK_OF(X509_REVOKED)
      OPENSSL_STACK *revoked;
      // STACK_OF(X509_EXTENSION)
      OPENSSL_STACK /* [0] */ *extensions;
      ASN1_ENCODING enc;
    } X509_CRL_INFO;

    // Note: this struct is trimmed
    struct X509_crl_st {
      /* actual signature */
      X509_CRL_INFO *crl;
      // trimmed
    } /* X509_CRL */ ;

    int X509_CRL_set_lastUpdate(X509_CRL *x, const ASN1_TIME *tm);
    int X509_CRL_set_nextUpdate(X509_CRL *x, const ASN1_TIME *tm);
  ]]
end