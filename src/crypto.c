/* Crypto primitives on top of OpenSSL libcrypto, plus the SPAKE2+ verifier.
 *
 * Matter has exactly one cipher suite, so there is nothing to negotiate:
 *   - Hash:       SHA-256
 *   - MAC / KDF:  HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA256
 *   - AEAD:       AES-128-CCM, 13-byte nonce, 16-byte tag ("MIC")
 *   - Curve:      NIST P-256 (secp256r1) for ECDSA and ECDH
 *   - PAKE:       SPAKE2+ on P-256 (PASE only)
 *
 * We use OpenSSL's older EC_KEY / EC_POINT APIs (deprecated in 3.0 but still
 * present) because SPAKE2+ needs direct point arithmetic, and the same API
 * then keeps the ECDSA/ECDH code uniform. OPENSSL_SUPPRESS_DEPRECATED hides
 * the deprecation warnings.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "matter.h"

#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

static EC_GROUP *grp;   /* the P-256 curve, created once at startup */

void crypto_init(void)
{
    grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
}

void sha256(const void *d, size_t n, uint8_t out[32])
{
    SHA256(d, n, out);
}

void hmac_sha256(const uint8_t *key, size_t kl, const void *d, size_t n, uint8_t out[32])
{
    unsigned int l = 32;
    HMAC(EVP_sha256(), key, (int)kl, d, n, out, &l);
}

/* HKDF = Extract (PRK = HMAC(salt, ikm)) then Expand (with 'info').
 * An empty salt is equivalent to a salt of 32 zero bytes, which is what the
 * spec means by "salt = nil"; we simply don't set it in that case. */
int hkdf_sha256(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il,
                const char *info, uint8_t *out, size_t outl)
{
    int ok = 0;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!c || EVP_PKEY_derive_init(c) <= 0 || EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()) <= 0)
        goto out;
    if (sl && EVP_PKEY_CTX_set1_hkdf_salt(c, salt, (int)sl) <= 0)
        goto out;
    if (EVP_PKEY_CTX_set1_hkdf_key(c, ikm, (int)il) <= 0)
        goto out;
    if (EVP_PKEY_CTX_add1_hkdf_info(c, (const uint8_t *)info, (int)strlen(info)) <= 0)
        goto out;
    ok = EVP_PKEY_derive(c, out, &outl) > 0;
out:
    EVP_PKEY_CTX_free(c);
    return ok ? 0 : -1;
}

/* AES-128-CCM in one function for both directions (enc = 1 / 0).
 * CCM quirks in OpenSSL's EVP API, in the order they must happen:
 *   1. set nonce length (13) and tag length (16; on decrypt, also the tag)
 *   2. set key + nonce
 *   3. announce the total plaintext length (CCM needs it up front)
 *   4. feed the AAD
 *   5. feed the data in a single call
 * On decrypt, step 5 itself fails if the tag does not verify. */
static int ccm(int enc, const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad,
               size_t al, const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16])
{
    int ok = 0, l;
    uint8_t dummy;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c || EVP_CipherInit_ex(c, EVP_aes_128_ccm(), NULL, NULL, NULL, enc) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_CCM_SET_IVLEN, 13, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_CCM_SET_TAG, 16, enc ? NULL : tag) != 1)
        goto out;
    if (EVP_CipherInit_ex(c, NULL, NULL, key, nonce, enc) != 1)
        goto out;
    if (EVP_CipherUpdate(c, NULL, &l, NULL, (int)n) != 1)
        goto out;
    if (al && EVP_CipherUpdate(c, NULL, &l, aad, (int)al) != 1)
        goto out;
    /* 'dummy' avoids passing NULL buffers when n == 0 */
    if (EVP_CipherUpdate(c, n ? out : &dummy, &l, n ? in : &dummy, (int)n) != 1)
        goto out;
    if (enc) {
        if (EVP_CipherFinal_ex(c, out + l, &l) != 1 ||
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_CCM_GET_TAG, 16, tag) != 1)
            goto out;
    }
    ok = 1;
out:
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

int aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t al,
                    const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[16])
{
    return ccm(1, key, nonce, aad, al, pt, n, ct, tag);
}

/* Returns -1 if the tag does not verify (tampered data or wrong key). */
int aes_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t al,
                    const uint8_t *ct, size_t n, uint8_t *pt, const uint8_t tag[16])
{
    return ccm(0, key, nonce, aad, al, ct, n, pt, (uint8_t *)tag);
}

/* ---------------------------------------------------------------- P-256 */
/* Keys are kept as raw bytes in p256_key and converted to OpenSSL objects on
 * demand. Slightly wasteful, but it keeps OpenSSL types out of matter.h and
 * makes keys trivial to store in the state file. */

/* EC point -> 65-byte uncompressed encoding 0x04 || X || Y */
static int point_encode(const EC_POINT *pt, uint8_t out[65])
{
    return EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, out, 65, NULL) == 65 ? 0 : -1;
}

/* Bytes -> EC point. Accepts compressed (33 bytes) or uncompressed (65)
 * input and rejects points that are not on the curve - important when the
 * point comes from the network (invalid-curve attacks). */
static EC_POINT *point_decode(const uint8_t *in, size_t n)
{
    EC_POINT *pt = EC_POINT_new(grp);
    if (EC_POINT_oct2point(grp, pt, in, n, NULL) != 1) {
        EC_POINT_free(pt);
        return NULL;
    }
    return pt;
}

/* Build an OpenSSL EC_KEY from a raw private scalar (public = d * G). */
static EC_KEY *eckey_from_priv(const uint8_t priv[32])
{
    EC_KEY *e = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *d = BN_bin2bn(priv, 32, NULL);
    EC_POINT *pub = EC_POINT_new(grp);
    EC_POINT_mul(grp, pub, d, NULL, NULL, NULL);
    EC_KEY_set_private_key(e, d);
    EC_KEY_set_public_key(e, pub);
    BN_free(d);
    EC_POINT_free(pub);
    return e;
}

int p256_keygen(p256_key *k)
{
    EC_KEY *e = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    int ok = EC_KEY_generate_key(e) == 1 &&
             BN_bn2binpad(EC_KEY_get0_private_key(e), k->priv, 32) == 32 &&
             point_encode(EC_KEY_get0_public_key(e), k->pub) == 0;
    EC_KEY_free(e);
    return ok ? 0 : -1;
}

int p256_from_priv(p256_key *k)
{
    EC_KEY *e = eckey_from_priv(k->priv);
    int r = point_encode(EC_KEY_get0_public_key(e), k->pub);
    EC_KEY_free(e);
    return r;
}

/* Load a SEC1 "EC PRIVATE KEY" DER blob (the format of the test DAC key). */
int p256_from_der(const uint8_t *der, size_t n, p256_key *k)
{
    const uint8_t *p = der;
    EC_KEY *e = d2i_ECPrivateKey(NULL, &p, (long)n);
    if (!e)
        return -1;
    BN_bn2binpad(EC_KEY_get0_private_key(e), k->priv, 32);
    EC_KEY_free(e);
    return p256_from_priv(k);
}

/* ECDSA-SHA256. OpenSSL produces a DER-encoded SEQUENCE{r, s}; Matter wants
 * the fixed-size raw form r||s (32 + 32 bytes), so we unpack it. */
int p256_sign(const p256_key *k, const void *msg, size_t n, uint8_t sig[64])
{
    uint8_t h[32];
    const BIGNUM *r, *s;
    sha256(msg, n, h);
    EC_KEY *e = eckey_from_priv(k->priv);
    ECDSA_SIG *es = ECDSA_do_sign(h, 32, e);
    EC_KEY_free(e);
    if (!es)
        return -1;
    ECDSA_SIG_get0(es, &r, &s);
    BN_bn2binpad(r, sig, 32);
    BN_bn2binpad(s, sig + 32, 32);
    ECDSA_SIG_free(es);
    return 0;
}

/* Verify a raw r||s signature against a 65-byte public key. 0 = valid. */
int p256_verify(const uint8_t pub[65], const void *msg, size_t n, const uint8_t sig[64])
{
    uint8_t h[32];
    int ok = 0;
    EC_POINT *pt = point_decode(pub, 65);
    if (!pt)
        return -1;
    sha256(msg, n, h);
    EC_KEY *e = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_public_key(e, pt);
    ECDSA_SIG *es = ECDSA_SIG_new();
    ECDSA_SIG_set0(es, BN_bin2bn(sig, 32, NULL), BN_bin2bn(sig + 32, 32, NULL));
    ok = ECDSA_do_verify(h, 32, es, e) == 1;
    ECDSA_SIG_free(es);
    EC_KEY_free(e);
    EC_POINT_free(pt);
    return ok ? 0 : -1;
}

/* ECDH: the shared secret is the X coordinate of priv * peer_pub (32 bytes).
 * Used by CASE; HKDF then turns it into actual keys. */
int p256_ecdh(const p256_key *k, const uint8_t peer[65], uint8_t secret[32])
{
    EC_POINT *pt = point_decode(peer, 65);
    if (!pt)
        return -1;
    EC_KEY *e = eckey_from_priv(k->priv);
    int n = ECDH_compute_key(secret, 32, pt, e, NULL);
    EC_KEY_free(e);
    EC_POINT_free(pt);
    return n == 32 ? 0 : -1;
}

/* PKCS#10 Certificate Signing Request for a freshly generated operational
 * key. The commissioner only cares about the public key and that the CSR is
 * self-signed by it (proof of possession); the subject "O=CSR" is a filler.
 * The resulting NOC is issued by the commissioner's CA, in Matter TLV form. */
int p256_csr(const p256_key *k, uint8_t *out, size_t *outlen)
{
    int ok = 0;
    EVP_PKEY *pk = EVP_PKEY_new();
    X509_REQ *req = X509_REQ_new();
    EVP_PKEY_assign_EC_KEY(pk, eckey_from_priv(k->priv));
    X509_REQ_set_version(req, 0);
    X509_NAME_add_entry_by_txt(X509_REQ_get_subject_name(req), "O", MBSTRING_ASC,
                               (const unsigned char *)"CSR", -1, -1, 0);
    if (X509_REQ_set_pubkey(req, pk) == 1 && X509_REQ_sign(req, pk, EVP_sha256()) > 0) {
        int l = i2d_X509_REQ(req, NULL);
        if (l > 0 && (size_t)l <= *outlen) {
            uint8_t *p = out;
            i2d_X509_REQ(req, &p);
            *outlen = (size_t)l;
            ok = 1;
        }
    }
    X509_REQ_free(req);
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

/* -------------------------------------------------------------- SPAKE2+ */
/*
 * SPAKE2+ is an *augmented* PAKE: two parties who share a low-entropy secret
 * (the 8-digit setup passcode) derive a strong shared key, and an eavesdropper
 * or impostor gets at most one online guess per attempt. "Augmented" means the
 * device (the verifier) does not even need the passcode, only a verifier
 * derived from it - so a compromised device doesn't leak the passcode.
 *
 * Notation (G = P-256 generator, M and N = fixed public points):
 *
 *   Setup (both sides):
 *     w0s || w1s = PBKDF2(passcode, salt, iterations, 80 bytes)
 *     w0 = w0s mod n,   w1 = w1s mod n        (n = curve order)
 *     Verifier stores (w0, L = w1*G)          <- spake_verifier()
 *
 *   Prover (commissioner)      ->  X = x*G + w0*M          (Pake1)
 *   Verifier (us)              ->  Y = y*G + w0*N          (Pake2)
 *   Both compute (we do it as the verifier):
 *     Z = y*(X - w0*M)  (= x*y*G, which only someone knowing w0 can unmask)
 *     V = y*L           (= y*w1*G; the prover computes w1*(Y - w0*N))
 *
 *   Transcript TT = len||Context || len||A || len||B || len||M || len||N
 *                   || len||X || len||Y || len||Z || len||V || len||w0
 *     (each len is 8 bytes little-endian; identities A and B are empty)
 *   Ka || Ke = SHA256(TT)                         16 + 16 bytes
 *   KcA || KcB = HKDF(Ka, info="ConfirmationKeys") 16 + 16 bytes
 *   cA = HMAC(KcA, Y)   sent by prover in Pake3, we check it
 *   cB = HMAC(KcB, X)   sent by us in Pake2, prover checks it
 *   Ke -> HKDF(info="SessionKeys") -> the PASE session keys
 *
 * If the commissioner used the wrong passcode, Z and V differ, so cA won't
 * match and we reject in Pake3.
 */

/* SPAKE2+ P-256 generator points M and N (compressed), as used by Matter. */
static const char *M_HEX = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
static const char *N_HEX = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

/* Derive (w0, L) from the passcode. The passcode is fed to PBKDF2 as a
 * 4-byte little-endian integer, not as decimal text. Each half of the PBKDF2
 * output is 40 bytes (32 + 8 extra) so that reducing mod n is unbiased. */
int spake_verifier(uint32_t passcode, const uint8_t *salt, size_t sl, uint32_t iters,
                   uint8_t w0out[32], uint8_t Lout[65])
{
    uint8_t pc[4], ws[80];
    put_le32(pc, passcode);
    if (PKCS5_PBKDF2_HMAC((const char *)pc, 4, salt, (int)sl, (int)iters, EVP_sha256(), 80, ws) != 1)
        return -1;
    BN_CTX *bc = BN_CTX_new();
    const BIGNUM *order = EC_GROUP_get0_order(grp);
    BIGNUM *w0 = BN_bin2bn(ws, 40, NULL), *w1 = BN_bin2bn(ws + 40, 40, NULL);
    BN_nnmod(w0, w0, order, bc);
    BN_nnmod(w1, w1, order, bc);
    BN_bn2binpad(w0, w0out, 32);
    EC_POINT *L = EC_POINT_new(grp);
    EC_POINT_mul(grp, L, w1, NULL, NULL, bc);
    int r = point_encode(L, Lout);
    EC_POINT_free(L);
    BN_free(w0);
    BN_free(w1);
    BN_CTX_free(bc);
    return r;
}

/* Append one length-prefixed item (8-byte LE length) to the transcript. */
static void tt_add(uint8_t *tt, size_t *len, const uint8_t *d, size_t n)
{
    put_le64(tt + *len, n);
    *len += 8;
    if (n)
        memcpy(tt + *len, d, n);
    *len += n;
}

/* Verifier side of SPAKE2+, done in one shot when Pake1 (X) arrives.
 * Inputs:  our verifier (w0, L), the PASE context hash, the prover's X.
 * Outputs: Y and cB (to send in Pake2), the cA we expect in Pake3, and Ke
 *          (the secret the session keys are derived from). */
int spake_respond(const uint8_t w0b[32], const uint8_t Lb[65], const uint8_t context[32],
                  const uint8_t X[65], uint8_t Y[65], uint8_t cB[32], uint8_t cA_expected[32],
                  uint8_t Ke[16])
{
    int ret = -1;
    uint8_t mc[33], nc[33], Mu[65], Nu[65], Z[65], V[65];
    hex2bin(M_HEX, mc, 33);
    hex2bin(N_HEX, nc, 33);

    BN_CTX *bc = BN_CTX_new();
    EC_POINT *M = point_decode(mc, 33), *N = point_decode(nc, 33);
    EC_POINT *Xp = point_decode(X, 65), *Lp = point_decode(Lb, 65);   /* X validated on-curve */
    EC_POINT *Yp = EC_POINT_new(grp), *T = EC_POINT_new(grp);
    EC_POINT *Zp = EC_POINT_new(grp), *Vp = EC_POINT_new(grp);
    BIGNUM *w0 = BN_bin2bn(w0b, 32, NULL), *y = BN_new();
    if (!M || !N || !Xp || !Lp)
        goto out;

    /* our ephemeral secret y, uniformly in [1, n-1] */
    do {
        BN_rand_range(y, EC_GROUP_get0_order(grp));
    } while (BN_is_zero(y));

    /* Y = y*G + w0*N */
    EC_POINT_mul(grp, Yp, y, N, w0, bc);
    /* Z = y*(X - w0*M), V = y*L  (cofactor h = 1 for P-256) */
    EC_POINT_mul(grp, T, NULL, M, w0, bc);   /* T = w0*M        */
    EC_POINT_invert(grp, T, bc);             /* T = -w0*M       */
    EC_POINT_add(grp, T, Xp, T, bc);         /* T = X - w0*M    */
    EC_POINT_mul(grp, Zp, NULL, T, y, bc);
    EC_POINT_mul(grp, Vp, NULL, Lp, y, bc);
    if (EC_POINT_is_at_infinity(grp, Zp))
        goto out;
    /* all points enter the transcript in uncompressed form (65 bytes) */
    if (point_encode(Yp, Y) || point_encode(Zp, Z) || point_encode(Vp, V) ||
        point_encode(M, Mu) || point_encode(N, Nu))
        goto out;

    /* TT = Context || A || B || M || N || X || Y || Z || V || w0, each with an 8-byte LE length */
    uint8_t tt[8 * 10 + 32 + 65 * 6 + 32];
    size_t tl = 0;
    tt_add(tt, &tl, context, 32);
    tt_add(tt, &tl, NULL, 0);                /* A: prover identity (empty in Matter) */
    tt_add(tt, &tl, NULL, 0);                /* B: verifier identity (empty) */
    tt_add(tt, &tl, Mu, 65);
    tt_add(tt, &tl, Nu, 65);
    tt_add(tt, &tl, X, 65);
    tt_add(tt, &tl, Y, 65);
    tt_add(tt, &tl, Z, 65);
    tt_add(tt, &tl, V, 65);
    tt_add(tt, &tl, w0b, 32);

    uint8_t K[32], Kc[32];
    sha256(tt, tl, K);                      /* Ka = K[0..16], Ke = K[16..32] */
    memcpy(Ke, K + 16, 16);
    if (hkdf_sha256(NULL, 0, K, 16, "ConfirmationKeys", Kc, 32))
        goto out;
    hmac_sha256(Kc, 16, Y, 65, cA_expected);  /* cA = HMAC(KcA, Y) */
    hmac_sha256(Kc + 16, 16, X, 65, cB);      /* cB = HMAC(KcB, X) */
    ret = 0;
out:
    EC_POINT_free(M); EC_POINT_free(N); EC_POINT_free(Xp); EC_POINT_free(Lp);
    EC_POINT_free(Yp); EC_POINT_free(T); EC_POINT_free(Zp); EC_POINT_free(Vp);
    BN_free(w0); BN_free(y);
    BN_CTX_free(bc);
    return ret;
}
