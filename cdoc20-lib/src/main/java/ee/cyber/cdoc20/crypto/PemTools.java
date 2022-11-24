package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.util.Resources;
import ee.cyber.cdoc20.util.SkLdapUtil;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.AbstractMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

/**
 * Utility class to deal with EC and RSA keys and certificates in PEM format.
 */
public final class PemTools {
    private static final Logger log = LoggerFactory.getLogger(PemTools.class);

    private PemTools() {
    }

    /**
     * Load EC or RSA pub key from PEM
     *
     * EC key:
     * openssl ec -in key.pem -pubout -out public.pem
     * <code>
     * -----BEGIN PUBLIC KEY-----
     * MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhEZdaw/m5tmqIrhonGPKG0ZHLPo7fJLO
     * IwtYw/3/xEPCnRWKyfisJzOkfKyF6g51JyyRYhdzsw6bvE1I1Tr3V4M0C/p+u0Ii
     * 3cnq0xOn+boyF6FzZGQfDtpF/97wA7gw
     * -----END PUBLIC KEY-----
     * <code/>
     *
     * ASN.1:
     * <pre>
     SEQUENCE (2 elem)
     SEQUENCE (2 elem)
     OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
     OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
     BIT STRING (776 bit) 0000010001111001011000011010011100101001101001111001000111111000011010…
     * </pre>
     *
     * RSA is standard PEM encoded RSA public key
     * @param pem
     * @return public key
     */
    public static PublicKey loadPublicKey(String pem) throws IOException {

        Object parsed = new PEMParser(new StringReader(pem)).readObject();
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(parsed);

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return converter.getPublicKey(publicKeyInfo);
    }

    /**
     * Load key pair (EC or RSA) from OpenSSL generated PEM file:
     * openssl ecparam -name secp384r1 -genkey -noout -out key.pem
     * Example key PEM:
     * <pre>
     * -----BEGIN EC PRIVATE KEY-----
     * MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd
     * 4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j
     * C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd
     * yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=
     * -----END EC PRIVATE KEY-----
     * </pre>
     * Decoded PEM has ASN.1 structure:
     * <pre>
     SEQUENCE (4 elem)
     INTEGER 1
     OCTET STRING (48 byte) 61D54013F37D8D876657BDD73925B36FDC1704652624F747AC52448F1668365C4BA803…
     [0] (1 elem)
     OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
     [1] (1 elem)
     BIT STRING (776 bit) 0000010010000100010001100101110101101011000011111110011011100110110110…
     </pre>
     *
     * @param pem OpenSSL generated private key in PEM
     * @return KeyPair decoded from PEM
     * @throw InvalidKeyException if key is not supported by CDOC2 lib
     */
    public static KeyPair loadKeyPair(String pem) throws GeneralSecurityException, IOException {

        Object parsed = new PEMParser(new StringReader(pem)).readObject();
        PEMKeyPair pemKeyPair = (PEMKeyPair) parsed;

        PrivateKey privateKey = new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        PublicKey publicKey = pemKeyPair.getPublicKeyInfo() == null
            ? null
            : new JcaPEMKeyConverter().getPublicKey(pemKeyPair.getPublicKeyInfo());

        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        // openssl pkcs12 -in INFILE.p12 -nodes -nocerts | openssl ec -out OUTFILE.key
        // doesn't export public key part, which is added by
        // openssl ecparam -name secp384r1 -genkey -noout -out key.pem
        // Derive public key from EC private if public key was not in PEM
        // see ECKeysTest::testLoadKeyPairFromPemShort
        if (publicKey == null) {
            if ((privateKey != null) && ("EC".equals(privateKey.getAlgorithm()))) {
                keyPair = ECKeys.deriveECPubKeyFromPrivKey((ECPrivateKey) privateKey);
            } else {
                throw new IllegalArgumentException("No public key found");
            }
        }

        publicKey = keyPair.getPublic();
        if ("EC".equals(publicKey.getAlgorithm())) {
            if (!ECKeys.isECSecp384r1(keyPair)) {
                throw new InvalidKeyException("Not an EC keypair with secp384r1 curve");
            }
        } else if ("RSA".equals(publicKey.getAlgorithm())) {
            // all RSA keys are considered good. Shorter will fail during encryption as OAEP takes some space
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            // no good way to check RSA key length as BigInteger can start with 00 and that changes bit-length
            if (rsaPublicKey.getModulus().bitLength() <= 512) {
                new InvalidKeyException("RSA key does not meet length requirements");
            }
        } else {
            throw new InvalidKeyException("Unsupported key algorithm " + publicKey.getAlgorithm());
        }
        return keyPair;
    }

    /**
     * Load key pair from OpenSSL generated PEM file:
     * openssl ecparam -name secp384r1 -genkey -noout -out key.pem
     * Example key PEM:
     * <pre>
     * -----BEGIN EC PRIVATE KEY-----
     * MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd
     * 4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j
     * C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd
     * yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=
     * -----END EC PRIVATE KEY-----
     * </pre>
     * @param pemFile OpenSSL generated EC private key in PEM
     * @return EC KeyPair decoded from PEM
     */
    public static KeyPair loadKeyPair(File pemFile) throws GeneralSecurityException, IOException {
        return loadKeyPair(Files.readString(pemFile.toPath()));
    }

    /**
     * Load first private key and certificate from .p12 (PKCS12) input stream
     * @param p12InputStream InputStream containing PKCS12 structure
     * @param passwd optional password for p12 input stream
     * @return private key and certificate pair
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static AbstractMap.SimpleEntry<PrivateKey, X509Certificate> loadKeyCertFromP12(InputStream p12InputStream,
                                                                                          @Nullable char[] passwd)
            throws GeneralSecurityException, IOException {

        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        clientKeyStore.load(p12InputStream, passwd);
        final List<String> entryNames = new LinkedList<>();
        clientKeyStore.aliases().asIterator().forEachRemaining(alias -> {
            try {
                log.debug("{} key={} cert={}", alias, clientKeyStore.isKeyEntry(alias),
                        clientKeyStore.isCertificateEntry(alias));
                entryNames.add(alias);
            } catch (KeyStoreException e) {
                log.error("KeyStoreException", e);
            }
        });

        if (entryNames.size() != 1) {
            if (entryNames.isEmpty()) {
                log.error("No keys found from .p12");
                throw new KeyManagementException("No keys found from p12");
            } else {
                log.warn("Multiple keys found {}", entryNames);
            }
        }

        String keyAlias = entryNames.get(0);

        log.info("Loading key \"{}\"", keyAlias);
        KeyStore.PrivateKeyEntry privateKeyEntry =
                (KeyStore.PrivateKeyEntry) clientKeyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(passwd));
        if (privateKeyEntry == null) {
            log.error("Entry not found {}", keyAlias);
            throw new KeyStoreException("Key not found for " + keyAlias);
        }

        PrivateKey key = privateKeyEntry.getPrivateKey();
        X509Certificate cert = (X509Certificate) privateKeyEntry.getCertificate();

        return new AbstractMap.SimpleEntry<>(key, cert);
    }

    public static Map<PublicKey, String> loadPubKeysWithKeyLabel(File[] pubPemFiles) throws IOException {
        Map<PublicKey, String> map = new LinkedHashMap<>();
        if (pubPemFiles != null) {
            for (File f : pubPemFiles) {
                map.put(loadPublicKey(Files.readString(f.toPath())), "N/A");
            }
        }
        return map;
    }

    /**
     * Load public key (EC or RSA) from InputStream
     * @param certIs Certificate InputStream in PEM (.cer) format
     * @return public key paired with key label {@link SkLdapUtil#getKeyLabel(X509Certificate)}
     * @throws CertificateException
     */
    public static Map.Entry<PublicKey, String> loadCertKeyWithLabel(InputStream certIs) throws CertificateException {
        var cert = loadCertificate(certIs);
        PublicKey publicKey = cert.getPublicKey();
        String label = SkLdapUtil.getKeyLabel(cert);
        return Map.entry(publicKey, label);
    }

    /**
     * Load a certificate from input stream
     * @param is the input stream
     * @return the X509Certificate
     * @throws CertificateException when parsing fails
     */
    public static X509Certificate loadCertificate(InputStream is) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(is);
    }

    /**
     * Parse public keys (EC or RSA) from certificate files
     * @param certFiles Array of certificates files in PEM (.cer) format
     * @return public keys parsed from certFiles. Public keys are paired with key label
     *          {@link SkLdapUtil#getKeyLabel(X509Certificate)}
     * @throws CertificateException
     * @throws IOException
     */
    public static Map<PublicKey, String> loadCertKeysWithLabel(File[] certFiles)
            throws CertificateException, IOException {

        Map<PublicKey, String> map = new LinkedHashMap<>();

        if (certFiles != null) {
            for (File f : certFiles) {
                InputStream in = Files.newInputStream(f.toPath());
                Map.Entry<PublicKey, String> keyLabelEntry = loadCertKeyWithLabel(in);
                map.put(keyLabelEntry.getKey(), keyLabelEntry.getValue());
            }
        }

        return map;
    }

    /**
     * Load keypair from P12 representation.
     * @param p12 the .p12 file with optional password, i.e filename:password
     * @return the key pair
     */
    public static KeyPair loadKeyPairFromP12File(String p12) throws GeneralSecurityException, IOException {
        String[] split = p12.split(":");
        if (split.length < 1 || split.length > 2) {
            throw new IllegalArgumentException("Invalid .p12 file: " + p12);
        }

        String p12FileName = split.length == 2 ? split[0] : p12;
        char[] p12Passwd = split.length == 2 ? split[1].toCharArray() : null;

        var keyCert = PemTools.loadKeyCertFromP12(
            Resources.getResourceAsStream(p12FileName), p12Passwd);

        PrivateKey key = keyCert.getKey();
        X509Certificate cert = keyCert.getValue();
        PublicKey publicKey = cert.getPublicKey();
        return new KeyPair(publicKey, key);
    }
}
