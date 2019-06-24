#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <cstddef>
#include <fstream>
#include <memory>

void generate_dh_pem(const char* dh_path) {
    const int prime_len = 2048;
    const int generator = DH_GENERATOR_2;
    DH* dh = DH_new();
    if (dh == NULL) {
        LOG(error) << "Alloc for dh failed";
        ERR_print_errors_fp(stderr);
        abort();
    }
    LOG(info) << "Generating DH parameter, this might take a while...";

    const int res =
        DH_generate_parameters_ex(dh, prime_len, generator, nullptr);

    if (!res) {
        LOG(error) << "Alloc for dh failed";
        ERR_print_errors_fp(stderr);
        abort();
    }

    LOG(info) << "DH parameter done!";
    FILE* pFile = NULL;
    pFile = fopen(dh_path, "wt");
    PEM_write_DHparams(pFile, dh);
    fclose(pFile);
}

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

    rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pk, rsa)) {
        abort();
        goto err;
    }
    rsa = NULL;

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
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (const unsigned char*)"AU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)"localhost", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (const unsigned char*)"Loki", -1, -1, 0);

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
    return (1);
err:
    return (0);
}

void generate_cert(const char* cert_path, const char* key_path) {
    BIO* bio_err;
    X509* x509 = NULL;
    EVP_PKEY* pkey = NULL;

    OpenSSL_add_all_digests();

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    mkcert(&x509, &pkey, 2048, 1, 10000);

    // X509_print_fp(stdout, x509);

    FILE* key_f = fopen(key_path, "wt");
    if (!PEM_write_PrivateKey(key_f, pkey, NULL, NULL, 0, NULL, NULL))
        abort();
    fclose(key_f);
    FILE* cert_f = fopen(cert_path, "wt");
    PEM_write_X509(cert_f, x509);
    fclose(cert_f);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    CRYPTO_cleanup_all_ex_data();

    //    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
}

inline void load_server_certificate(const boost::filesystem::path& base_path,
                                    boost::asio::ssl::context& ctx) {
    /*
        The certificate was generated from CMD.EXE on Windows 10 using:

        winpty openssl dhparam -out dh.pem 2048
        winpty openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days
       10000 -out cert.pem -subj "//C=US\ST=CA\L=Los
       Angeles\O=Beast\CN=www.example.com"
    */
    const auto cert_path_str = (base_path / "cert.pem").string();
    const auto key_path_str = (base_path / "key.pem").string();
    const auto dh_path_str = (base_path / "dh.pem").string();

    const auto cert_path = cert_path_str.c_str();
    const auto key_path = key_path_str.c_str();
    const auto dh_path = dh_path_str.c_str();

    if (!boost::filesystem::exists(cert_path) ||
        !boost::filesystem::exists(key_path)) {
        generate_cert(cert_path, key_path);
    }
    if (!boost::filesystem::exists(dh_path)) {
        generate_dh_pem(dh_path);
    }

    ctx.set_options(boost::asio::ssl::context::default_workarounds |
                    boost::asio::ssl::context::no_sslv2 |
                    boost::asio::ssl::context::single_dh_use);

    ctx.use_certificate_chain_file(cert_path);

    ctx.use_private_key_file(key_path,
                             boost::asio::ssl::context::file_format::pem);

    ctx.use_tmp_dh_file(dh_path);
}
