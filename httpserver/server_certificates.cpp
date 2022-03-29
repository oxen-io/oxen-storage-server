#include "server_certificates.h"

extern "C" {
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
}

#include "oxen_logger.h"

#include <cstddef>

namespace oxen {

namespace {

    /* Add extension using V3 code: we can set the config file as NULL
     * because we wont reference any other sections.
     */

    int add_ext(X509* cert, int nid, char* value) {
        X509_EXTENSION* ex;
        X509V3_CTX ctx;
        /* This sets the 'context' of the extensions. */
        /* No configuration database */
        X509V3_set_ctx_nodb(&ctx);
        /* Issuer and subject certs: both the target since it is self signed,
         * no request and no CRL
         */
        X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
        ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
        if (!ex)
            return 0;

        X509_add_ext(cert, ex, -1);
        X509_EXTENSION_free(ex);
        return 1;
    }

    int mkcert(X509** x509p, EVP_PKEY** pkeyp, int bits, int serial, int days) {
        X509* x;
        EVP_PKEY* pk;
        RSA* rsa;
        X509_NAME* name = NULL;
        BIGNUM* bne = NULL;
        int res = 0;

        if ((pkeyp == NULL) || (*pkeyp == NULL)) {
            if ((pk = EVP_PKEY_new()) == NULL) {
                abort();
                return (0);
            }
        } else
            pk = *pkeyp;

        if ((x509p == NULL) || (*x509p == NULL)) {
            if ((x = X509_new()) == NULL)
                goto err;
        } else
            x = *x509p;

        bne = BN_new();
        rsa = RSA_new();

        if (BN_set_word(bne, RSA_F4) != 1) {
            goto err;
        }

        if (!RSA_generate_key_ex(rsa, bits, bne, NULL)) {
            goto err;
        }

        // https://www.openssl.org/docs/man1.0.2/man3/EVP_PKEY_assign_RSA.html
        // "[rsa] will be freed when the parent pkey is freed."
        if (!EVP_PKEY_assign_RSA(pk, rsa)) {
            goto err;
        }

        X509_set_version(x, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
        X509_gmtime_adj(X509_get_notBefore(x), 0);
        X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
        X509_set_pubkey(x, pk);

        name = X509_get_subject_name(x);

        /* This function creates and adds the entry, working out the
         * correct string type and performing checks on its length.
         * Normally we'd check the return value for errors...
         */
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"AU", -1, -1, 0);
        X509_NAME_add_entry_by_txt(
                name, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);
        X509_NAME_add_entry_by_txt(
                name, "O", MBSTRING_ASC, (const unsigned char*)"Oxen", -1, -1, 0);

        /* Its self signed so set the issuer name to be the same as the
         * subject.
         */
        X509_set_issuer_name(x, name);

        /* Add various extensions: standard extensions */
        //    add_ext(x, NID_basic_constraints, "critical,CA:FALSE");
        //    add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

        add_ext(x, NID_subject_key_identifier, (char*)"hash");

        /* Some Netscape specific extensions */
        //    add_ext(x, NID_netscape_cert_type, "sslCA");

        //    add_ext(x, NID_netscape_comment, "example comment extension");

#ifdef CUSTOM_EXT
        /* Maybe even add our own extension based on existing */
        {
            int nid;
            nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
            X509V3_EXT_add_alias(nid, NID_netscape_comment);
            add_ext(x, nid, "example comment alias");
        }
#endif

        if (!X509_sign(x, pk, EVP_sha256()))
            goto err;

        *x509p = x;
        *pkeyp = pk;
        res = 1;
    err:
        BN_free(bne);
        // rsa will be freed automatically when pk is freed by the caller
        return (res);
    }

}  // namespace

void generate_dh_pem(const std::filesystem::path& dh_path) {
    const int prime_len = 2048;
    const int generator = DH_GENERATOR_2;
    DH* dh = DH_new();
    if (dh == NULL) {
        OXEN_LOG(err, "Alloc for dh failed");
        ERR_print_errors_fp(stderr);
        abort();
    }
    OXEN_LOG(info, "Generating DH parameter, this might take a while...");

    const int res = DH_generate_parameters_ex(dh, prime_len, generator, nullptr);

    if (!res) {
        OXEN_LOG(err, "Alloc for dh failed");
        ERR_print_errors_fp(stderr);
        abort();
    }

    OXEN_LOG(info, "DH parameter done!");
    FILE* pFile = NULL;
    pFile = fopen(dh_path.u8string().c_str(), "wt");
    PEM_write_DHparams(pFile, dh);
    fclose(pFile);
}

void generate_cert(const std::filesystem::path& cert_path, const std::filesystem::path& key_path) {
    BIO* bio_err;
    X509* x509 = NULL;
    EVP_PKEY* pkey = NULL;
    FILE* key_f = NULL;
    FILE* cert_f = NULL;

    OpenSSL_add_all_digests();

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!mkcert(&x509, &pkey, 2048, 1, 10000))
        goto err;
    // X509_print_fp(stdout, x509);

    key_f = fopen(key_path.u8string().c_str(), "wt");
    if (!PEM_write_PrivateKey(key_f, pkey, NULL, NULL, 0, NULL, NULL))
        goto err;
    cert_f = fopen(cert_path.u8string().c_str(), "wt");
    PEM_write_X509(cert_f, x509);

err:
    fclose(cert_f);
    fclose(key_f);
    X509_free(x509);
    EVP_PKEY_free(pkey);

    CRYPTO_cleanup_all_ex_data();

    //    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
}

}  // namespace oxen
