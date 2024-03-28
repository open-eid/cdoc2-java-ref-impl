package ee.cyber.cdoc2.server.datagen;

import ee.cyber.cdoc2.crypto.ECKeys;
import ee.cyber.cdoc2.crypto.RsaUtils;
import ee.cyber.cdoc2.crypto.KeyAlgorithm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Utility class for generating keys and certificates
 */
@Slf4j
public final class CertUtil {
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String CERT_SIG_ALGO = "SHA512WITHECDSA";
    private static final Duration CERT_VALIDITY = Duration.ofDays(365L);
    private static final int RSA_KEY_SIZE = 2048;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private CertUtil() {
        // utility class
    }

    @SneakyThrows
    static X509Certificate generateCertificate(X500Principal subject, KeyPair subjectKeyPair,
            X500Principal signedBy, KeyPair signedByKeyPair, String cn) {

        var notBefore = Instant.now();
        var notAfter = notBefore.plus(CERT_VALIDITY);

        var altNames = new ASN1Encodable[] {
            new GeneralName(GeneralName.dNSName, cn)
        };

        var certBuilder = new JcaX509v3CertificateBuilder(
            signedBy, BigInteger.ONE,
            new Date(notBefore.toEpochMilli()), new Date(notAfter.toEpochMilli()),
            subject,
            subjectKeyPair.getPublic()
        );

        try {
            certBuilder
                .addExtension(Extension.subjectAlternativeName, false, new DERSequence(altNames));

            final ContentSigner signer = new JcaContentSignerBuilder(CERT_SIG_ALGO)
                .setProvider(BC)
                .build(signedByKeyPair.getPrivate());

            X509CertificateHolder certHolder = certBuilder.build(signer);

            log.info(
                "Created cert(issuer={}, subject={}, type={})",
                certHolder.getIssuer(), certHolder.getSubject(), subjectKeyPair.getPrivate().getAlgorithm()
            );

            return getCertificate(certHolder);
        } catch (Exception e) {
            log.error("Failed to create certificate", e);
            throw e;
        }
    }

    @SneakyThrows
    public static KeyPair generateEcKeyPair() {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ECKeys.SECP_384_R_1);
        try {
            KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance(KeyAlgorithm.Algorithm.EC.name(), BC);
            keyPairGenerator.initialize(ecSpec, SecureRandom.getInstanceStrong());
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            log.error("Failed to generate EC key pair", e);
            throw e;
        }
    }

    @SneakyThrows
    public static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance(KeyAlgorithm.Algorithm.RSA.name());
            keyPairGenerator.initialize(RSA_KEY_SIZE, SecureRandom.getInstanceStrong());
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            log.error("Failed to generate RSA key pair", e);
            throw e;
        }
    }


    @SneakyThrows
    static X509Certificate getCertificate(X509CertificateHolder holder) {
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
    }

    @SneakyThrows
    public static String encodePublicKey(ECPublicKey pubKey) {
        return Base64.getEncoder().encodeToString(ECKeys.encodeEcPubKeyForTls(pubKey));
    }

    @SneakyThrows
    public static String encodePublicKey(RSAPublicKey pubKey) {
        return Base64.getEncoder().encodeToString(RsaUtils.encodeRsaPubKey(pubKey));
    }

}
