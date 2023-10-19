/* selftest.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * https://www.wolfssl.com
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_SELFTEST there */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_SELFTEST

#include <wolfssl/wolfcrypt/selftest.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/asn.h>

#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048
#include <wolfssl/certs_test.h>   /* rsa 2048 bit key */


enum {
    CAVP_AES_KEY_SZ     = 32,
    CAVP_AES_IV_SZ      = AES_BLOCK_SIZE,
    CAVP_AES_PLAIN_SZ   = 64,
    CAVP_AES_CBC_SZ     = CAVP_AES_PLAIN_SZ,
    CAVP_AES_CIPHER_SZ  = CAVP_AES_PLAIN_SZ,

    CAVP_GCM_KEY_SZ     = 32,
    CAVP_GCM_AUTH_SZ    = 16,
    CAVP_GCM_CHECK_SZ   = 16,
    CAVP_GCM_TAG_SZ     = 16,
    CAVP_GCM_PLAIN_SZ   = 32,
    CAVP_GCM_CIPHER_SZ  = CAVP_GCM_PLAIN_SZ,
    CAVP_GCM_OUT_SZ     = CAVP_GCM_PLAIN_SZ,
    CAVP_GCM_IV_SZ      = 12,

    CAVP_DES3_KEY_SZ    = 24,
    CAVP_DES3_PLAIN_SZ  = CAVP_DES3_KEY_SZ,
    CAVP_DES3_CBC_SZ    = CAVP_DES3_KEY_SZ,
    CAVP_DES3_CIPHER_SZ = CAVP_DES3_KEY_SZ,
    CAVP_DES3_IV_SZ     = 8,

    CAVP_HMAC_DIGEST_SZ = 64,
    CAVP_HMAC_KEY_SZ    = CAVP_HMAC_DIGEST_SZ,

    CAVP_DRBG_EA_SZ     = 48,
    CAVP_DRBG_EB_SZ     = 32,
    CAVP_DRBG_OUT_SZ    = 128,

    CAVP_RSA_SIG_SZ     = 256,
    CAVP_RSA_RESULT_SZ  = CAVP_RSA_SIG_SZ,
    CAVP_RSA_MOD_SZ     = 2048,
    CAVP_RSA_PRIME_SZ   = 1024,
    CAVP_RSA_MOD_SHORT  = 128,

    CAVP_ECC_256_SZ     = 32,

    CAVP_DH_KEY_SZ      = 256 /* 2048-bit */
};


/* convert hex string to binary, store size, 0 success (free mem on failure) */
static int ConvertHexToBin(const char* h1, byte* b1, word32* b1Sz,
                           const char* h2, byte* b2, word32* b2Sz,
                           const char* h3, byte* b3, word32* b3Sz,
                           const char* h4, byte* b4, word32* b4Sz)
{
    int ret;
    word32 h1Sz, h2Sz, h3Sz, h4Sz, tempSz;
    (void) h1Sz;
    (void) h2Sz;
    (void) h3Sz;
    (void) h4Sz;

    /* b1 */
    if (h1 && b1 && b1Sz) {
        h1Sz = (int) XSTRLEN(h1);
        tempSz = h1Sz / 2;
        if (tempSz > *b1Sz || tempSz <= 0) {
            return BUFFER_E;
        }
        *b1Sz = tempSz;

        ret = Base16_Decode((const byte*)h1, h1Sz, b1, b1Sz);

        if (ret != 0) {
            return ret;
        }
    }

    /* b2 */
    if (h2 && b2 && b2Sz) {
        h2Sz = (int)XSTRLEN(h2);
        tempSz = h2Sz / 2;
        if (tempSz > *b2Sz || tempSz <= 0) {
            return BUFFER_E;
        }
        *b2Sz = tempSz;

        ret = Base16_Decode((const byte*)h2, h2Sz, b2, b2Sz);
        if (ret != 0) {
            return ret;
        }
    }

    /* b3 */
    if (h3 && b3 && b3Sz) {
        h3Sz = (int)XSTRLEN(h3);
        tempSz = h3Sz / 2;
        if (tempSz > *b3Sz || tempSz <= 0) {
            return BUFFER_E;
        }
        *b3Sz =  tempSz;

        ret = Base16_Decode((const byte*)h3, h3Sz, b3, b3Sz);
        if (ret != 0) {
            return ret;
        }
    }

    /* b4 */
    if (h4 && b4 && b4Sz) {
        h4Sz = (int)XSTRLEN(h4);
        tempSz = h4Sz / 2;
        if (tempSz > *b4Sz || tempSz <= 0) {
            return BUFFER_E;
        }
        *b4Sz =  tempSz;

        ret = Base16_Decode((const byte*)h4, h4Sz, b4, b4Sz);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}



/* 0 on success */
#ifndef NO_AES
static int AesKnownAnswerTest(const char* key, const char* iv,
                              const char* plainText, const char* cbc)
{
    Aes   aes;

    word32 keySz   = CAVP_AES_KEY_SZ;
    word32 ivSz    = CAVP_AES_IV_SZ;
    word32 plainSz = CAVP_AES_PLAIN_SZ;
    word32 cbcSz   = CAVP_AES_CBC_SZ;

    byte binKey   [CAVP_AES_KEY_SZ];    /* AES_Key is 32 bytes */
    byte binIv    [CAVP_AES_IV_SZ];     /* AES_IV is 32 bytes */
    byte binPlain [CAVP_AES_PLAIN_SZ];  /* AES_Plain is 128 bytes */
    byte binCbc   [CAVP_AES_CBC_SZ];    /* AES_Cbc is 128 bytes */
    byte cipher   [CAVP_AES_CIPHER_SZ]; /* for cipher (same as plainSz */

    int ret = ConvertHexToBin(key, binKey, &keySz,
                              iv,  binIv,  &ivSz,
                              plainText, binPlain,  &plainSz,
                              cbc, binCbc,  &cbcSz);
    if (ret != 0)
        return ret;

    ret = wc_AesSetKey(&aes, binKey, keySz, binIv, AES_ENCRYPTION);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesCbcEncrypt(&aes, cipher, binPlain, plainSz);
    if (ret != 0) {
        return ret;
    }

    if (XMEMCMP(cipher, binCbc, plainSz) != 0) {
        return -1;
    }

    ret = wc_AesSetKey(&aes, binKey, keySz, binIv, AES_DECRYPTION);
    if (ret != 0) {
        return ret;
    }

    /* decrypt cipher in place back to plain for verify */
    ret = wc_AesCbcDecrypt(&aes, cipher, cipher, plainSz);
    if (ret != 0) {
        return ret;
    }

    if (XMEMCMP(cipher, binPlain, plainSz) != 0) {
        return -1;
    }

    return 0; 
}
#endif /* NO_AES */


/* 0 on success */
#ifdef HAVE_AESGCM
static int AesGcm_KnownAnswerTest(int decrypt,
                                  const char* key, const char* iv,
                                  const char* plain, const char* auth,
                                  const char* cipher, const char* tag)
{
    Aes aes;

    byte binKey    [CAVP_GCM_KEY_SZ];    /* key */
    byte binIv     [CAVP_GCM_IV_SZ];     /* iv */
    byte binPlain  [CAVP_GCM_PLAIN_SZ];  /* plain */
    byte binAuth   [CAVP_GCM_AUTH_SZ];   /* auth */
    byte binCipher [CAVP_GCM_CIPHER_SZ]; /* cipher */
    byte binTag    [CAVP_GCM_TAG_SZ];    /* tag */
    byte out       [CAVP_GCM_OUT_SZ];    /* out */
    byte check     [CAVP_GCM_CHECK_SZ];  /* check */

    word32 binKeySz   = CAVP_GCM_KEY_SZ,     binIvSz   = CAVP_GCM_IV_SZ,
           binPlainSz = CAVP_GCM_PLAIN_SZ,   binAuthSz = CAVP_GCM_AUTH_SZ,
           binCipherSz = CAVP_GCM_CIPHER_SZ, binTagSz  = CAVP_GCM_TAG_SZ;

    int ret = ConvertHexToBin(key, binKey, &binKeySz, iv, binIv, &binIvSz,
                              NULL, NULL, NULL, NULL, NULL, NULL);
    if (ret != 0)
        return ret;

    ret = ConvertHexToBin(plain, binPlain, &binPlainSz,
                          auth, binAuth, &binAuthSz,
                          cipher, binCipher, &binCipherSz,
                          tag, binTag, &binTagSz);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(&aes, binKey, binKeySz);
    if (ret != 0) {
        return ret;
    }

    if (decrypt) {
        ret = wc_AesGcmDecrypt(&aes, out, binCipher,
                               binCipherSz, binIv, binIvSz,
                               binTag, binTagSz,
                               binAuth, binAuthSz);
        if (ret != 0) {
            return ret;
        }

        if (XMEMCMP(binPlain, out, binPlainSz) != 0) {
            return -1;
        }
    }
    else {

        ret = wc_AesGcmEncrypt(&aes, out, binPlain, binPlainSz,
                               binIv, binIvSz,
                               check, binTagSz,
                               binAuth, binAuthSz);

        if (ret != 0) {
            return -1;
        }

        if (XMEMCMP(binCipher, out, binCipherSz) != 0 &&
            XMEMCMP(binTag, check, binTagSz) != 0) {

            return -1;
        }
    }

    return 0;
}
#endif /* HAVE_AESGCM */


/* 0 on success */
#ifndef NO_DES3
static int Des3_KnownAnswerTest(const char* key, const char* iv,
                                const char* plainText, const char* cbc)
{
    Des3  des3;

    word32 keySz   = CAVP_DES3_KEY_SZ;
    word32 ivSz    = CAVP_DES3_IV_SZ;
    word32 plainSz = CAVP_DES3_PLAIN_SZ;
    word32 cbcSz   = CAVP_DES3_CBC_SZ;

    byte binKey    [CAVP_DES3_KEY_SZ];    /* key */
    byte binIv     [CAVP_DES3_IV_SZ];     /* iv */
    byte binPlain  [CAVP_DES3_PLAIN_SZ];  /* plain */
    byte binCbc    [CAVP_DES3_CBC_SZ];    /* cbc */
    byte cipher    [CAVP_DES3_CIPHER_SZ]; /* cipher */

    int ret = ConvertHexToBin(key, binKey, &keySz,
                              iv,  binIv,  &ivSz,
                              plainText, binPlain,  &plainSz,
                              cbc, binCbc,  &cbcSz);
    if (ret != 0)
        return ret;

    ret = wc_Des3_SetKey(&des3, binKey, binIv, DES_ENCRYPTION);
    if (ret != 0) {
        return ret;
    }

    ret = wc_Des3_CbcEncrypt(&des3, cipher, binPlain, plainSz);
    if (ret != 0) {
        return ret;
    }

    if (XMEMCMP(cipher, binCbc, plainSz) != 0) {
        return -1;
    }

    ret = wc_Des3_SetKey(&des3, binKey, binIv, DES_DECRYPTION);
    if (ret != 0) {
        return ret;
    }

    /* decrypt cipher in place back to plain for verify */
    ret = wc_Des3_CbcDecrypt(&des3, cipher, cipher, plainSz);
    if (ret != 0) {
        return ret;
    }

    if (XMEMCMP(cipher, binPlain, plainSz) != 0) {
        return -1;
    }


    return 0; 
}
#endif /* NO_DES3 */


/* 0 on success */
static int HMAC_KnownAnswerTest(int type, const char* key, const char* msg,
                                const char* digest)
{
    Hmac        hmac;
    const byte* binMsg    = (const byte*)msg;
    byte        final[MAX_DIGEST_SIZE];

    word32 msgSz    = (word32)XSTRLEN(msg);
    word32 digestSz = CAVP_HMAC_DIGEST_SZ;
    word32 keySz    = CAVP_HMAC_KEY_SZ;

    byte binDigest [CAVP_HMAC_DIGEST_SZ]; /* Longest HMAC Digest 128 bytes */
    byte binKey    [CAVP_HMAC_KEY_SZ];    /* Longest HMAC Key is 128 bytes */

    int ret = ConvertHexToBin(digest, binDigest, &digestSz,
                              key, binKey, &keySz,
                              NULL, NULL, NULL,
                              NULL, NULL, NULL);
    if (ret != 0)
        return ret;

    ret = wc_HmacSetKey(&hmac, type, binKey, keySz);
    if (ret != 0) {
        return ret;
    }

    ret = wc_HmacUpdate(&hmac, binMsg, msgSz);
    if (ret != 0) {
        return ret;
    }

    ret = wc_HmacFinal(&hmac, final);
    if (ret != 0) {
        return ret;
    }

    if (XMEMCMP(final, binDigest, digestSz) != 0) {
        return -1;
    }


    return 0;
}


/* 0 on success */
#ifdef HAVE_HASHDRBG
static int DRBG_KnownAnswerTest(int reseed, const char* entropyA,
                                const char* entropyB, const char* output)
{
    word32 binEntropyASz = CAVP_DRBG_EA_SZ;
    word32 binEntropyBSz = CAVP_DRBG_EB_SZ;
    word32 binOutputSz   = CAVP_DRBG_OUT_SZ;

    byte check[SHA256_DIGEST_SIZE * 4];

    byte binEntropyA [CAVP_DRBG_EA_SZ];  /* entropyA */
    byte binEntropyB [CAVP_DRBG_EB_SZ];  /* entropyB */
    byte binOutput   [CAVP_DRBG_OUT_SZ]; /* output */

    int ret = ConvertHexToBin(entropyA, binEntropyA, &binEntropyASz,
                              entropyB, binEntropyB, &binEntropyBSz,
                              output, binOutput, &binOutputSz,
                              NULL, NULL, NULL);

    if (ret != 0)
        return ret;

    /* Test Body */
    ret = wc_RNG_HealthTest(reseed, binEntropyA, binEntropyASz,
                                    binEntropyB, binEntropyBSz,
                                    check, sizeof(check));
    if (ret != 0) {
        return ret;
    }

    if (XMEMCMP(binOutput, check, sizeof(check)) != 0) {
        return -1;
    }

    return 0;
}
#endif /* HAVE_HASHDRBG */


#ifdef HAVE_ECC_CDH

static int ECC_CDH_KnownAnswerTest(const char* ax, const char* ay,
                                   const char* d, const char* ix,
                                   const char* iy, const char* z)
{
    ecc_key pub_key, priv_key;

    word32 aSz  = CAVP_ECC_256_SZ;
    word32 bSz  = CAVP_ECC_256_SZ;

    byte sharedA[CAVP_ECC_256_SZ] = {0};
    byte sharedB[CAVP_ECC_256_SZ] = {0};

    /* setup private and public keys */
    int ret = wc_ecc_init(&pub_key);
    if (ret != 0) {
        return ret;
    }
    ret = wc_ecc_init(&priv_key);
    if (ret != 0) {
        wc_ecc_free(&pub_key);
        return ret;
    }

    ret = wc_ecc_set_flags(&priv_key, WC_ECC_FLAG_COFACTOR);
    if (ret == 0) {
        ret = wc_ecc_import_raw(&pub_key, ax, ay, NULL, "SECP256R1");
    }
    if (ret == 0) {
        ret = wc_ecc_import_raw(&priv_key, ix, iy, d, "SECP256R1");
    }

    /* compute ECC Cofactor shared secret */
    if (ret == 0) {
        ret = wc_ecc_shared_secret(&priv_key, &pub_key, sharedA, &aSz);
    }

    /* read in expected Z */
    if (ret == 0) {
        ret = Base16_Decode((const byte*)z, (word32)XSTRLEN(z), sharedB, &bSz);
    }

    /* compare results */
    if (ret == 0) {
        if (aSz != bSz || XMEMCMP(sharedA, sharedB, aSz) != 0) {
            ret = -1;
        }
    }

    wc_ecc_free(&priv_key);
    wc_ecc_free(&pub_key);

    return ret;
}

#endif /* HAVE_ECC_CDH */

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)

static int ECDSA_PairwiseAgreeTest(int type, const char* msg)
{
    ecc_key     ecc;
    WC_RNG      rng;
    byte        msgDigest[MAX_DIGEST_SIZE];
    byte        msgSigned[(CAVP_ECC_256_SZ+1)*2 + 6];
    word32      msgSz = (word32)XSTRLEN(msg);
    word32      msgDigestSz = 0;
    word32      msgSignedSz = sizeof(msgSigned);
    word32      idx = 0;
    int         verify = 0;
    int         ret;

    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        return ret;
    }

    ret = wc_EccPrivateKeyDecode(ecc_clikey_der_256, &idx, &ecc,
                                 (word32)sizeof_ecc_clikey_der_256);
    if (ret != 0) {
        wc_ecc_free(&ecc);
        return ret;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ecc_free(&ecc);
        return ret;
    }

    switch (type) {
        case WC_SHA256 :
        {
            Sha256 sha256;

            wc_InitSha256(&sha256);
            wc_Sha256Update(&sha256, (const byte*)msg, msgSz);
            wc_Sha256Final(&sha256, msgDigest);
            msgDigestSz = SHA256_DIGEST_SIZE;
            break;
        }

        default:
            wc_ecc_free(&ecc);
            wc_FreeRng(&rng);
            return -1;
    }

    ret = wc_ecc_sign_hash(msgDigest, msgDigestSz, msgSigned, &msgSignedSz,
                           &rng, &ecc);
    if (ret != 0) {
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_ecc_verify_hash(msgSigned, msgSignedSz, msgDigest, msgDigestSz,
                             &verify, &ecc);
    if (ret != 0 || verify != 1) {
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        return ret;
    }

    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);

    return 0;
}

#endif /* HAVE_ECC && HAVE_ECC_SIGN && HAVE_ECC_VERIFY */


#ifndef NO_RSA
static int RsaSignPKCS1v15_KnownAnswerTest(int type, const char* msg,
                                           const char* sig)
{
    RsaKey      rsa;
    WC_RNG      rng;
    const byte* binMsg = (const byte*)msg;
    byte        final[MAX_DIGEST_SIZE];
    byte        verify[MAX_DIGEST_SIZE];
    word32 msgSz    = (word32)XSTRLEN(msg);
    word32 sigSz    = CAVP_RSA_SIG_SZ;
    word32 digestSz = 0;
    word32 verifySz = (word32)sizeof(verify);
    word32 resultSz = 0;
    word32 idx      = 0;

    byte binSig    [CAVP_RSA_SIG_SZ];    /* signature */
    byte result    [CAVP_RSA_RESULT_SZ]; /* result */

    int ret = ConvertHexToBin(sig, binSig, &sigSz,
                              NULL, NULL, NULL,
                              NULL, NULL, NULL,
                              NULL, NULL, NULL);
    if (ret != 0)
        return ret;

    resultSz = sigSz;

    ret = wc_InitRsaKey(&rsa, NULL);
    if (ret != 0) {
        return ret;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa);
        return ret;
    }

#ifdef WC_RSA_BLINDING
    ret = wc_RsaSetRNG(&rsa, &rng);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return ret;
    }
#endif


    switch (type) {
        case WC_SHA256 :
        {
            Sha256 sha256;

            wc_InitSha256(&sha256);
            wc_Sha256Update(&sha256, binMsg, msgSz);
            wc_Sha256Final(&sha256, final);
            digestSz = SHA256_DIGEST_SIZE;

            break;
        } 

        default:
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return -1;
    }

    ret = wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &rsa,
                                 sizeof_client_key_der_2048);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_RsaSSL_Sign(final, digestSz, result, resultSz, &rsa, &rng);
    if (ret != (int)sigSz) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return ret;
    }

    if (XMEMCMP(result, binSig, sigSz) != 0) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return -1;
    }

    ret = wc_RsaSSL_Verify(result, sigSz, verify, verifySz, &rsa);
    if (ret != (int)digestSz) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return ret;
    }

    if (XMEMCMP(verify, final, digestSz) != 0) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return -1;
    }

    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);

    return 0;
}
#endif /* NO_RSA */

#if !defined(NO_RSA) && defined(WC_RSA_PSS)
static int RsaSignPSS_PairwiseAgreeTest(int type, const char* msg)
{
    RsaKey           rsa;
    WC_RNG           rng;
    byte             msgDigest[MAX_DIGEST_SIZE];
    byte             msgSigned[CAVP_RSA_RESULT_SZ]; /* result */
    byte             msgVerify[CAVP_RSA_RESULT_SZ];
    word32           msgSz = (word32)XSTRLEN(msg);
    word32           msgDigestSz = 0;
    word32           msgSignedSz = sizeof(msgSigned);
    word32           msgVerifySz = sizeof(msgVerify);
    word32           idx = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    int              mgf = WC_MGF1NONE;
    int              ret;

    ret = wc_InitRsaKey(&rsa, NULL);
    if (ret != 0) {
        return ret;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa);
        return ret;
    }

    switch (type) {
        case WC_SHA256 :
        {
            Sha256 sha256;

            wc_InitSha256(&sha256);
            wc_Sha256Update(&sha256, (const byte*)msg, msgSz);
            wc_Sha256Final(&sha256, msgDigest);
            msgDigestSz = SHA256_DIGEST_SIZE;
            hashType = WC_HASH_TYPE_SHA256;
            mgf = WC_MGF1SHA256;

            break;
        }

        default:
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return -1;
    }

    ret = wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &rsa,
                                 sizeof_client_key_der_2048);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_RsaPSS_Sign(msgDigest, msgDigestSz, msgSigned, msgSignedSz,
                         hashType, mgf, &rsa, &rng);
    if (ret < 0) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return ret;
    }
    else
        msgSignedSz = ret;

    ret = wc_RsaPSS_Verify(msgSigned, msgSignedSz, msgVerify, msgVerifySz,
                           hashType, mgf, &rsa);
    if (ret < 0) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return ret;
    }
    else
        msgVerifySz = ret;

    ret = wc_RsaPSS_CheckPadding(msgDigest, msgDigestSz,
                                 msgVerify, msgVerifySz, hashType);

    if (ret < 0) {
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return ret;
    }

    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);

    return 0;
}
#endif /* NO_RSA && WC_RSA_PSS */


#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
static int RsaProbablyPrime_KnownAnswerTest(int expectedRes, int modSz,
                       const char* e, const char* p, const char* q)
{
    byte binE[CAVP_RSA_MOD_SHORT/8];
    byte binP[CAVP_RSA_PRIME_SZ/8];
    byte binQ[CAVP_RSA_PRIME_SZ/8];
    int res = 0;
    word32 binESz, binPSz, binQSz;

	binESz = sizeof(binE);
	binPSz = sizeof(binP);
	binQSz = sizeof(binQ);

    int ret = ConvertHexToBin(e, binE, &binESz,
                              p, binP, &binPSz,
                              q, binQ, &binQSz,
                              NULL, NULL, NULL);
    if (ret != 0)
        return ret;

    ret = wc_CheckProbablePrime(binP, binPSz, binQ, binQSz,
                                binE, binESz, modSz, &res);
    if (ret != 0)
        return -1;

    if (expectedRes != res)
        return -1;

    return 0;
}
#endif /* NO_RSA CYASSL_KEY_GEN HAVE_FIPS v2 */


#ifndef NO_DH

static int DhPrimitiveZ_KnownAnswerTest(const char* p, const char* g,
                                        const char* xClient,
                                        const char* yServer,
                                        const char* zVerify)
{
    DhKey dh;
    Sha256 sha;
    byte pFlat[CAVP_DH_KEY_SZ];
    byte gFlat[CAVP_DH_KEY_SZ];
    byte yServerFlat[CAVP_DH_KEY_SZ];
    byte xClientFlat[CAVP_DH_KEY_SZ];
    byte zVerifyFlat[SHA256_DIGEST_SIZE];
    byte z[CAVP_DH_KEY_SZ];
    byte zHash[SHA256_DIGEST_SIZE];
    word32 pFlatSz = sizeof(pFlat);
    word32 gFlatSz = sizeof(gFlat);
    word32 yServerFlatSz = sizeof(yServerFlat);
    word32 xClientFlatSz = sizeof(xClientFlat);
    word32 zVerifyFlatSz = sizeof(zVerifyFlat);
    word32 zSz = sizeof(z);
    int ret;

    ret = ConvertHexToBin(yServer, yServerFlat, &yServerFlatSz,
                          xClient, xClientFlat, &xClientFlatSz,
                          zVerify, zVerifyFlat, &zVerifyFlatSz,
                          NULL, NULL, NULL);
    if (ret != 0)
        return ret;

    ret = ConvertHexToBin(p, pFlat, &pFlatSz, g, gFlat, &gFlatSz,
                          NULL, NULL, NULL, NULL, NULL, NULL);
    if (ret != 0)
        return ret;

    ret = wc_InitDhKey(&dh);
    if (ret != 0) {
        return ret;
    }

    ret = wc_DhSetKey(&dh, pFlat, pFlatSz, gFlat, gFlatSz);
    if (ret != 0) {
        wc_FreeDhKey(&dh);
        return ret;
    }

    ret = wc_DhAgree(&dh, z, &zSz, xClientFlat, xClientFlatSz,
                     yServerFlat, yServerFlatSz);
    if (ret != 0) {
        wc_FreeDhKey(&dh);
        return ret;
    }

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, z, zSz);
    wc_Sha256Final(&sha, zHash);

    if (XMEMCMP(zHash, zVerifyFlat, zVerifyFlatSz) != 0)
        return -1;

    wc_FreeDhKey(&dh);
    return 0;
}

#endif /* NO_DH */


/* do all tests, 0 on success */
int wolfCrypt_SelfTest(void)
{
#ifndef NO_AES
    if (AesKnownAnswerTest(
             "2b7e151628aed2a6abf7158809cf4f3c",  /* 128-bit key */
             "000102030405060708090a0b0c0d0e0f",  /* iv */
             "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac" /* plainText */
             "9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a"
             "52eff69f2445df4f9b17ad2b417be66c3710",
             "7649abac8119b246cee98e9b12e9197d5086cb9b507219" /* cbc */
             "ee95db113a917678b273bed6b8e3c1743b7116e69e2222"
             "95163ff1caa1681fac09120eca307586e1a7"
             ) != 0) {
        return AES_KAT_FIPS_E;
    }

    if (AesKnownAnswerTest(
             "84fea1f2ffcbb968a1168639c8137bdb"   /* 256-bit key */
             "a18b4b049b80ff6c1c1445d472a70b47",
             "ad6c7d4c0cb2baa3189d0fa64b8ced4f",  /* iv */
             "8c320432ea6b98f464fc28b50f72a3f8"   /* plainText */
             "7011c4d848608ba6b1e8edd46a38cb11"
             "702c21b6ce6f8061b53fbedfcf70ec50"
             "d1b488855019f4add5d32731333ca3dc",
             "fbe9b8a2a90351a32565e2182e657f3b"   /* cbc */
             "b5d6dfdca59f1ce299da637415a9a234"
             "bf45bb1e7a49509bf62cf7724c9da4e7"
             "2705bcb1cec6842958089ed643eb7507"
             ) != 0) {
        return AES_KAT_FIPS_E;
    }
#endif

#ifdef HAVE_AESGCM
    if (AesGcm_KnownAnswerTest(0,
             "298efa1ccf29cf62ae6824bfc19557fc",                /* key */
             "6f58a93fe1d207fae4ed2f6d",                        /* iv */
             "cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac" /* plain */
             "63872daf16b93901",
             "021fafd238463973ffe80256e5b1c6b1",                /* auth */
             "dfce4e9cd291103d7fe4e63351d9e79d3dfd391e32671046" /* cipher */
             "58212da96521b7db",
             "542465ef599316f73a7a560509a2d9f2"                 /* tag */
             ) != 0) {
        return AESGCM_KAT_FIPS_E;
    }

    if (AesGcm_KnownAnswerTest(1,
             "afa272c03d0343f882008f6e163d6047",                /* key */
             "271ba21f8fdcac34dc93be54",                        /* iv */
             "f3ee01423f192c36033542221c5545dd939de52ada18b9e8" /* plain */
             "b72ba17d02c5dddd",
             "cdf5496a50214683304aec0a80337f9a",                /* auth */
             "36a4029c9e7d0307d31c29cea885bb6c8022452016a29754" /* cipher */
             "ba8a344c5bbfc3e1",
             "ed8d916c171f0688d7e7cca547ab3ab2"                 /* tag */
             ) != 0) {
        return AESGCM_KAT_FIPS_E;
    }

    if (AesGcm_KnownAnswerTest(0,
             "f0eaf7b41b42f4500635bc05d9cede11"                 /* key */
             "a5363d59a6288870f527bcffeb4d6e04",
             "18f316781077a595c72d4c07",                        /* iv */
             "400fb5ef32083b3abea957c4f068abad"                 /* plain */
             "50c8d86bbf9351fa72e7da5171df38f9",
             "42cade3a19204b7d4843628c425c2375",                /* auth */
             "7a1b61009dce6b7cd4d1ea0203b179f1"                 /* cipher */
             "219dd5ce7407e12ea0a4c56c71bb791b",
             "4419180b0b963b7289a4fa3f45c535a3"                 /* tag */
             ) != 0) {
        return AESGCM_KAT_FIPS_E;
    }

    if (AesGcm_KnownAnswerTest(1,
             "a68f043e1336dfa26625d18e40bdc595"                 /* key */
             "b54a3e458ac01d8f3c0f859c47a2df3f",
             "ff29fff9a2abcbd1ea4951d7",                        /* iv */
             "82d64a95b3a4b5ae5746312139d21f44"                 /* plain */
             "0d96611d92fb7ae4ab0d690857071e9a",
             "f96e3e30f9f0de510f0164d4c7637b05",                /* auth */
             "d7a8e9ec7860fb7e04bba31281e7feb3"                 /* cipher */
             "3bc996fd695347ddf2e49f699760e68b",
             "3f3a0eee090d684a61a16950d0b88379"                 /* tag */
             ) != 0) {
        return AESGCM_KAT_FIPS_E;
    }

#endif

#ifndef NO_DES3
    if (Des3_KnownAnswerTest(
            "385D7189A5C3D485E1370AA5D408082B5CCCCB5E19F2D90E",  /* key */
            "C141B5FCCD28DC8A",                                  /* iv  */
            "6E1BD7C6120947A464A6AAB293A0F89A563D8D40D3461B68",  /* plain */
            "6235A461AFD312973E3B4F7AA7D23E34E03371F8E8C376C9"   /* cbc */
             ) != 0) {
        return DES3_KAT_FIPS_E;
    }
#endif

#ifndef NO_SHA
    if (HMAC_KnownAnswerTest(SHA,                             /* type */
            "303132333435363738393a3b3c3d3e3f40414243",       /* key */
            "Sample #2",                                      /* msg */
            "0922D3405FAA3D194F82A45830737D5CC6C75D24"        /* digest */
            ) != 0) {
        return HMAC_KAT_FIPS_E;
    }
#endif

#ifndef NO_SHA256
    if (HMAC_KnownAnswerTest(WC_SHA256,                         /* type */
            "000102030405060708090A0B0C0D0E0F101112131415161"   /* key */
            "718191A1B1C1D1E1F",
            "Sample message for keylen<blocklen",               /* msg */
            "A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717"   /* digest */
            "FECF5480F0EBDF790"
            ) != 0) {
        return HMAC_KAT_FIPS_E;
    }
#endif

#ifdef CYASSL_SHA512
    if (HMAC_KnownAnswerTest(SHA512,                          /* type */
            "303132333435363738393a3b3c3d3e3f40414243",       /* key */
            "Sample #2",                                      /* msg */
            "809d44057c5b954105bd041316db0fac44d5a4d5d0892bd04e866412c0907768"
            "f187b77c4fae2c2f21a5b5659a4f4ba74702a3de9b51f145bd4f252742989905"
            /* digest */
            ) != 0) {
        return HMAC_KAT_FIPS_E;
    }
#endif

#ifndef NO_RSA
    if (RsaSignPKCS1v15_KnownAnswerTest(WC_SHA256,            /* type */
            "Everyone gets Friday off.",                      /* msg */
            "8CFA57979578B9D781C7F7EEDD21E962FC45D8B7CCDA68837"
            "D84E8345973856089C025A06F89F77D7C3694C483A6EF6B42"
            "EE69B8C2E01CC113F137F498890752EF6C6094D3819979122"
            "7928ED82D5BB50FB96A754F977D66FE75ABCF70F5D9448352"
            "26D30BF6F62D7B9CAFFA18179C5DABCE58BA497424A5AC8D6"
            "11814B726CF3294D0C238000DC2B775791925CA528F6B4947"
            "D3E4BA1F8CDF4C3E88E1AA2FCDAE461F6DF245DD3C39F980F"
            "D0FEC213FCB7B7D1679F4689D08538E16A8E0F357BADFD1F0"
            "D56C635B9E6E7CBD6E2F32F347AB9E07685166016EEF8F857"
            "37542185635688469BC08AF743B02B5C6FB5CED8924B20C14"
            "7B9F349FAA1943DBF677CA"
            /* signature */
            ) != 0) {
        return RSA_KAT_FIPS_E;
    }
#endif

#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    if (RsaSignPSS_PairwiseAgreeTest(WC_SHA256,          /* type */
            "Everyone gets Friday off."                  /* msg */
            ) != 0) {
        return RSAPSS_PAT_FIPS_E;
    }
#endif

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    if (RsaProbablyPrime_KnownAnswerTest(1, CAVP_RSA_MOD_SZ, /* modulus size */
            "df28ab", /* public exponent */
            "e021757c777288dacfe67cb2e59dc02c70a8cebf56262336592c"
            "18dcf466e0a4ed405318ac406bd79eca29183901a557db556dd0"
            "6f7c6bea175dcb8460b6b1bc05832b01eedf86463238b7cb6643"
            "deef66bc4f57bf8ff7ec7c4b8a8af14f478980aabedd42afa530"
            "ca47849f0151b7736aa4cd2ff37f322a9034de791ebe3f51", /* prime p */
            "ed1571a9e0cd4a42541284a9f98b54a6af67d399d55ef888b9fe"
            "9ef76a61e892c0bfbb87544e7b24a60535a65de422830252b45d"
            "2033819ca32b1a9c4413fa721f4a24ebb5510ddc9fd6f4c09dfc"
            "29cb9594650620ff551a62d53edc2f8ebf10beb86f483d463774"
            "e5801f3bb01c4d452acb86ecfade1c7df601cab68b065275" /* prime q */
            ) != 0) {
        return RSA_KAT_FIPS_E;
    }
#endif

#ifdef HAVE_HASHDRBG
    if (DRBG_KnownAnswerTest(0,
            "a65ad0f345db4e0effe875c3a2e71f42"
            "c7129d620ff5c119a9ef55f05185e0fb"
            "8581f9317517276e06e9607ddbcbcc2e", /* entropy + nonce input */
            NULL,                               /* no reseed */
            "d3e160c35b99f340b2628264d1751060"
            "e0045da383ff57a57d73a673d2b8d80d"
            "aaf6a6c35a91bb4579d73fd0c8fed111"
            "b0391306828adfed528f018121b3febd"
            "c343e797b87dbb63db1333ded9d1ece1"
            "77cfa6b71fe8ab1da46624ed6415e51c"
            "cde2c7ca86e283990eeaeb9112041552"
            "8b2295910281b02dd431f4c9f70427df"  /* pseudorandom output */
            ) != 0) {
        return DRBG_KAT_FIPS_E;
    }

    if (DRBG_KnownAnswerTest(1,
            "63363377e41e86468deb0ab4a8ed683f"
            "6a134e47e014c700454e81e95358a569"
            "808aa38f2a72a62359915a9f8a04ca68", /* entropy + nonce input */
            "e62b8a8ee8f141b6980566e3bfe3c049"
            "03dad4ac2cdf9f2280010a6739bc83d3", /* reseed entropy input */
            "04eec63bb231df2c630a1afbe724949d"
            "005a587851e1aa795e477347c8b05662"
            "1c18bddcdd8d99fc5fc2b92053d8cfac"
            "fb0bb8831205fad1ddd6c071318a6018"
            "f03b73f5ede4d4d071f9de03fd7aea10"
            "5d9299b8af99aa075bdb4db9aa28c18d"
            "174b56ee2a014d098896ff2282c955a8"
            "1969e069fa8ce007a180183a07dfae17"  /* pseudorandom output */
            ) != 0) {
        return DRBG_KAT_FIPS_E;
    }
#endif

#ifdef HAVE_ECC_CDH
    if (ECC_CDH_KnownAnswerTest(
                /* ax */
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
                /* ay */
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
                /* d */
        "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
                /* ix */
        "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
                /* iy */
        "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
                /* z */
        "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"
            ) != 0) {
        return ECC_CDH_KAT_FIPS_E;
    }
#endif

#ifndef NO_DH
    if (DhPrimitiveZ_KnownAnswerTest(
            /* p */
            "c7a528b2747cd4080d5da193285ef3eddf7bea8be391df9503c9f6a73372f6ee"
            "4e8b2cc0577bf7f8366a29b59286be32e1a13e60bea187e654b6c71268e39c97"
            "3ff220e4a8545cef5a85980d1c9687193faac4355370dee4a37acfc3a29c3e1c"
            "82faad94a2afc004ea1861fde4a9c25950a85264eb87175d047af23ad048d840"
            "50f8f0ea071672a6d210b545656c0556e94d2b4ab0b739eaf4d6c2d8d09c464f"
            "8d6afc1a8283ef3a6227d87ab6fef5e6208645a468bbba478d4b84dedb398689"
            "15e28317a7111ee75c028fe2ecfcf92453b89ff7d8c860e875b266d4455c2ac2"
            "626b6a748af0597ca9907405981d4e9af12451dad23a46f4219da89cc5be7453",
            /* g */
            "2fa3f79bb9cfb3fbaa4b19b8c0b5fb1e791da1c3426fb33c979ad2fcde6f984c"
            "c1578fb79125b646694ef937e2a4b1c45ff1ecb7847d4e2cc5761fa483116a9c"
            "cf628aa9c71c15cb37547ec1bd64930fb9a7569e90219b2d6ed82ad2cfee8b04"
            "4aefb475dfd0f89acb690b5021d7cacba9cbdcb517416bdbade00003dd9ea18d"
            "310e9c5734f8508ca57eb523b84b199600c130ce7bd0ab2f3dc151c10301fefc"
            "11bcd7f4fc628a84e58e4b34eb9e17406cfece2db09d7966b76582a13b31ebd7"
            "fd51bf57495144598300c9c1dc2f69237aba4e0d6d6aee1bdff125f5fee62735"
            "6759ba8c2f64dbef44565dde7875362b8e681cdf63aa2add4fa83b0a7509c3cc",
            /* xClient */
            "5b359fb62eea923b26727316a2a54126bd89a5b5015be6ac1b294ffaf180d1cb",
            /* yServer */
            "b503c9e08cf1461540eed4d794a8dc103fa47c3e1689cc3145b8f9bdeb1df99b"
            "d029f4431ce36b5854c7e16b8d076cf58023f7696fad93789a730a8b42d11345"
            "0903cea3555a39b3c1a9756dcd22915e5bb2ac62e4607f0c455da951b43135db"
            "37e171ddb4da8ae671a90f1bd288d634d4f18481d25c139d44672bbef0245928"
            "a9a78d1f5d28665eed690acdf0e06a82a3e4fdb9776a2705248f10ac638f6525"
            "03fd69d73ed46b4d0e47beb738d90913a48840d4a05f059aee4050572d6432c0"
            "a4a50e455d2b92195eadb7193c96f31e89d469b16ef9b5ddef006102652a90cd"
            "1d6d29f366f88321eb6ce0bdf6c567b302670df28ad42424dc8475a6b0153826",
            /* zVerify */
            "288cc3c9b62c6af7ae8ceaa61c1ebe3de7fe8040928b7154428fa3a08e148b27"
            ) != 0) {
        return DH_KAT_FIPS_E;
    }
#endif

#ifdef HAVE_ECC
    if (ECDSA_PairwiseAgreeTest(WC_SHA256, "Everyone gets Friday off.") != 0) {
        return ECDSA_PAT_FIPS_E;
    }
#endif

    return 0;  /* success */
}

#endif /* HAVE_SELFTEST */

