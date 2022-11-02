package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.crypto.ECKeys.EllipticCurve;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ECKeysTest {
    private static final Logger log = LoggerFactory.getLogger(ECKeysTest.class);

    @Test
    void testBigInteger() {
        byte[] neg = new BigInteger("-255").toByteArray(); //0xff, 0x01
        byte[] neg254 = new BigInteger("-254").toByteArray(); //0xff, 0x02
        byte[] zero = new BigInteger("0").toByteArray(); // 0x00
        byte[] pos127 = new BigInteger("127").toByteArray(); // 0x7f
        byte[] pos128 = new BigInteger("128").toByteArray(); // 0x00, 0x80
        byte[] pos = new BigInteger("255").toByteArray(); // 0x00, 0xff

        assertEquals(new BigInteger("255"), new BigInteger(1, new byte[] {(byte)0xff}));
        assertEquals(new BigInteger("255"), new BigInteger(1, new byte[] {(byte)0x00, (byte)0xff}));
    }

    @Test
    void testEcPubKeyEncodeDecode() throws GeneralSecurityException {
        log.trace("testEcPubKeyEncodeDecode()");

        KeyPair keyPair = ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1);
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        byte[] encodedEcPubKey = ECKeys.encodeEcPubKeyForTls(ecPublicKey);

        assertEquals(1 + ECKeys.SECP_384_R_1_LEN_BYTES * 2, encodedEcPubKey.length);
        assertEquals(1 + ECKeys.SECP_384_R_1_LEN_BYTES * 2, encodedEcPubKey.length);
        assertEquals(0x04, encodedEcPubKey[0]);

        ECPublicKey decoded = EllipticCurve.secp384r1.decodeFromTls(ByteBuffer.wrap(encodedEcPubKey));
        assertEquals(ecPublicKey.getW(), decoded.getW());
        assertEquals(ecPublicKey, decoded);
    }

    @Test
    void testLoadEcPrivKey() throws GeneralSecurityException, IOException {
        @SuppressWarnings("checkstyle:OperatorWrap")
        String privKeyPem =
                "-----BEGIN EC PRIVATE KEY-----\n" +
                        "MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd\n" +
                        "4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j\n" +
                        "C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd\n" +
                        "yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=\n" +
                        "-----END EC PRIVATE KEY-----\n";

        //        openssl ec -in key.pem -text -noout
        //        read EC key
        //        Private-Key: (384 bit)
        //        priv:
        //        61:d5:40:13:f3:7d:8d:87:66:57:bd:d7:39:25:b3:
        //        6f:dc:17:04:65:26:24:f7:47:ac:52:44:8f:16:68:
        //        36:5c:4b:a8:03:b6:af:4b:f9:1d:e0:7b:47:19:16:
        //        d1:45:b6
        //        pub:
        //        04:84:46:5d:6b:0f:e6:e6:d9:aa:22:b8:68:9c:63:
        //        ca:1b:46:47:2c:fa:3b:7c:92:ce:23:0b:58:c3:fd:
        //        ff:c4:43:c2:9d:15:8a:c9:f8:ac:27:33:a4:7c:ac:
        //        85:ea:0e:75:27:2c:91:62:17:73:b3:0e:9b:bc:4d:
        //        48:d5:3a:f7:57:83:34:0b:fa:7e:bb:42:22:dd:c9:
        //        ea:d3:13:a7:f9:ba:32:17:a1:73:64:64:1f:0e:da:
        //        45:ff:de:f0:03:b8:30
        //        ASN1 OID: secp384r1
        //        NIST CURVE: P-384
        String expectedSecretHex =
                "61d54013f37d8d876657bdd73925b36fdc1704652624f747ac52448f1668365c4ba803b6af4bf91de07b471916d145b6";

        ECPrivateKey key = ECKeys.loadECPrivateKey(privKeyPem);
        assertEquals("EC", key.getAlgorithm());
        assertEquals(expectedSecretHex, key.getS().toString(16));
    }


    @Test
    void testLoadEcPubKey() throws GeneralSecurityException, IOException {
        //openssl ecparam -name secp384r1 -genkey -noout -out key.pem
        //openssl ec -in key.pem -pubout -out public.pem
        @SuppressWarnings("checkstyle:OperatorWrap")
        String pubKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhEZdaw/m5tmqIrhonGPKG0ZHLPo7fJLO\n" +
                "IwtYw/3/xEPCnRWKyfisJzOkfKyF6g51JyyRYhdzsw6bvE1I1Tr3V4M0C/p+u0Ii\n" +
                "3cnq0xOn+boyF6FzZGQfDtpF/97wA7gw\n" +
                "-----END PUBLIC KEY-----\n";

//        openssl ec -in key.pem -text -noout
//        read EC key
//        Private-Key: (384 bit)
//        priv:
//        61:d5:40:13:f3:7d:8d:87:66:57:bd:d7:39:25:b3:
//        6f:dc:17:04:65:26:24:f7:47:ac:52:44:8f:16:68:
//        36:5c:4b:a8:03:b6:af:4b:f9:1d:e0:7b:47:19:16:
//        d1:45:b6
//        pub:
//        04:84:46:5d:6b:0f:e6:e6:d9:aa:22:b8:68:9c:63:
//        ca:1b:46:47:2c:fa:3b:7c:92:ce:23:0b:58:c3:fd:
//        ff:c4:43:c2:9d:15:8a:c9:f8:ac:27:33:a4:7c:ac:
//        85:ea:0e:75:27:2c:91:62:17:73:b3:0e:9b:bc:4d:
//        48:d5:3a:f7:57:83:34:0b:fa:7e:bb:42:22:dd:c9:
//        ea:d3:13:a7:f9:ba:32:17:a1:73:64:64:1f:0e:da:
//        45:ff:de:f0:03:b8:30
//        ASN1 OID: secp384r1
//        NIST CURVE: P-384
        String expectedHex = "04"
                + "84465d6b0fe6e6d9aa22b8689c63ca1b46472cfa3b7c92ce230b58c3fdffc443c29d158ac9f8ac2733a47cac85ea0e75"
                + "272c91621773b30e9bbc4d48d53af75783340bfa7ebb4222ddc9ead313a7f9ba3217a17364641f0eda45ffdef003b830";

        PublicKey publicKey = PemTools.loadPublicKey(pubKeyPem);
        assertEquals("EC", publicKey.getAlgorithm());

        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;


        assertTrue(ECKeys.isEcSecp384r1Curve(ecPublicKey));

        log.debug("{} {}", ECKeys.getCurveOid(ecPublicKey), ecPublicKey.getParams().toString());

        assertEquals(expectedHex, HexFormat.of().formatHex(ECKeys.encodeEcPubKeyForTls(ecPublicKey)));
    }

    @Test
    void testLoadEcKeyPairFromPem() throws GeneralSecurityException, IOException {
        @SuppressWarnings("checkstyle:OperatorWrap")
        String privKeyPem =
                "-----BEGIN EC PRIVATE KEY-----\n" +
                        "MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd\n" +
                        "4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j\n" +
                        "C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd\n" +
                        "yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=\n" +
                        "-----END EC PRIVATE KEY-----\n";

        //        openssl ec -in key.pem -text -noout
        //        read EC key
        //        Private-Key: (384 bit)
        //        priv:
        //        61:d5:40:13:f3:7d:8d:87:66:57:bd:d7:39:25:b3:
        //        6f:dc:17:04:65:26:24:f7:47:ac:52:44:8f:16:68:
        //        36:5c:4b:a8:03:b6:af:4b:f9:1d:e0:7b:47:19:16:
        //        d1:45:b6
        //        pub:
        //        04:84:46:5d:6b:0f:e6:e6:d9:aa:22:b8:68:9c:63:
        //        ca:1b:46:47:2c:fa:3b:7c:92:ce:23:0b:58:c3:fd:
        //        ff:c4:43:c2:9d:15:8a:c9:f8:ac:27:33:a4:7c:ac:
        //        85:ea:0e:75:27:2c:91:62:17:73:b3:0e:9b:bc:4d:
        //        48:d5:3a:f7:57:83:34:0b:fa:7e:bb:42:22:dd:c9:
        //        ea:d3:13:a7:f9:ba:32:17:a1:73:64:64:1f:0e:da:
        //        45:ff:de:f0:03:b8:30
        //        ASN1 OID: secp384r1
        //        NIST CURVE: P-384
        String expectedSecretHex =
                  "61d54013f37d8d876657bdd73925b36fdc1704652624f747ac52448f1668365c4ba803b6af4bf91de07b471916d145b6";
        String expectedPubHex = "04"
                + "84465d6b0fe6e6d9aa22b8689c63ca1b46472cfa3b7c92ce230b58c3fdffc443c29d158ac9f8ac2733a47cac85ea0e75"
                + "272c91621773b30e9bbc4d48d53af75783340bfa7ebb4222ddc9ead313a7f9ba3217a17364641f0eda45ffdef003b830";

        KeyPair keyPair = PemTools.loadFromPem(privKeyPem);
        ECPrivateKey ecPrivKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

        assertEquals("EC", ecPrivKey.getAlgorithm());
        assertEquals(expectedSecretHex, ecPrivKey.getS().toString(16));
        //No good way to verify secp384r1 curve - this might be different for non Sun Security Provider
        assertEquals("secp384r1 [NIST P-384] (1.3.132.0.34)", ecPrivKey.getParams().toString());

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(ecPrivKey.getParams());
        log.debug("{} oid {}", params.getProvider(), params.getParameterSpec(ECGenParameterSpec.class).getName());
        assertTrue(ECKeys.isEcSecp384r1Curve(ecPrivKey));

        assertEquals("EC", ecPublicKey.getAlgorithm());
        assertEquals(expectedPubHex, HexFormat.of().formatHex(ECKeys.encodeEcPubKeyForTls(ecPublicKey)));
    }

    @Test
    void testLoadCertWithLabel() throws CertificateException, IOException {

        @SuppressWarnings("checkstyle:OperatorWrap")
        final String igorCertificate =
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIGPjCCBCagAwIBAgIQWh4k6BI9wW9aAwcOMosU6DANBgkqhkiG9w0BAQsFADBr\n" +
                "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\n" +
                "czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNU\n" +
                "RUlELVNLIDIwMTUwHhcNMTcxMTA4MTMzMDU0WhcNMjIxMTA3MjE1OTU5WjCBlzEL\n" +
                "MAkGA1UEBhMCRUUxDzANBgNVBAoMBkVTVEVJRDEXMBUGA1UECwwOYXV0aGVudGlj\n" +
                "YXRpb24xJDAiBgNVBAMMG8W9QUlLT1ZTS0ksSUdPUiwzNzEwMTAxMDAyMTETMBEG\n" +
                "A1UEBAwKxb1BSUtPVlNLSTENMAsGA1UEKgwESUdPUjEUMBIGA1UEBRMLMzcxMDEw\n" +
                "MTAwMjEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATlalHxt8gcK5Asvap7DqJQI6PU\n" +
                "Tkoz0/FWBJwZGuzK733wy5RV2D+scuj6NsinEW4rQBxQegm3ASU1aNcRTiSO9sCv\n" +
                "GtGiptdt5w+9f7ddo855Lc/7C0vW0gG4tRLvob+jggJdMIICWTAJBgNVHRMEAjAA\n" +
                "MA4GA1UdDwEB/wQEAwIDiDCBiQYDVR0gBIGBMH8wcwYJKwYBBAHOHwMBMGYwLwYI\n" +
                "KwYBBQUHAgEWI2h0dHBzOi8vd3d3LnNrLmVlL3JlcG9zaXRvb3JpdW0vQ1BTMDMG\n" +
                "CCsGAQUFBwICMCcMJUFpbnVsdCB0ZXN0aW1pc2Vrcy4gT25seSBmb3IgdGVzdGlu\n" +
                "Zy4wCAYGBACPegECMCIGA1UdEQQbMBmBF2lnb3IuemFpa292c2tpQGVlc3RpLmVl\n" +
                "MB0GA1UdDgQWBBRWH+VJhoWaZU4WgnVNJCoDJNSRfTBhBggrBgEFBQcBAwRVMFMw\n" +
                "UQYGBACORgEFMEcwRRY/aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5L2NvbmRp\n" +
                "dGlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAgBgNVHSUBAf8EFjAU\n" +
                "BggrBgEFBQcDAgYIKwYBBQUHAwQwHwYDVR0jBBgwFoAUScDyRDll1ZtGOw04YIOx\n" +
                "1i0ohqYwgYMGCCsGAQUFBwEBBHcwdTAsBggrBgEFBQcwAYYgaHR0cDovL2FpYS5k\n" +
                "ZW1vLnNrLmVlL2VzdGVpZDIwMTUwRQYIKwYBBQUHMAKGOWh0dHBzOi8vc2suZWUv\n" +
                "dXBsb2FkL2ZpbGVzL1RFU1Rfb2ZfRVNURUlELVNLXzIwMTUuZGVyLmNydDBBBgNV\n" +
                "HR8EOjA4MDagNKAyhjBodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlkL3Rlc3Rf\n" +
                "ZXN0ZWlkMjAxNS5jcmwwDQYJKoZIhvcNAQELBQADggIBAG71HyOLLR7yUiEp18eK\n" +
                "vtmOLx4sd9rnvqgxtCy5AqoKkPirqJ9FRlg07GxZ4ReQCCLNLufsXzVbLCMCPzK6\n" +
                "UBJxeO+LwzGgsNSUQ4UbbETaA5M9zqq8GvuAdqFC+gipCcwyVmlCQ45gV5w2fV39\n" +
                "aZVjZjW9sJSlUubgxBRqfUsaIr/Ft1z1zmf/2cWWtOijP/iXTakJWQCrqM70EPWo\n" +
                "pFUWea8Ak7UHSETF8S6zvxigW9Fveufk0JZ76+iDFD+fKqCGurAveKJQxj3yVHIL\n" +
                "kFIhn1/8l6HterApbnwribJs3sCmgVd13na3cXideUG/SNLD3sQsS7UXS7E3Ksx7\n" +
                "5ZgQmAJ388lD5ouGo7XmOGJQFsahlANIwPlHSr30eofYxt8rzELXy1lcSNsiGXj1\n" +
                "xz1zkayfjiifHRurieeETm2hW/gla90CGUVHduHDxniQmbQOPbL/sr/0mebo+3j4\n" +
                "IlFpIqJXO72sM0e3hIw59aJSHwQf2WTPkVm+Sm8XZ8UOHNpkLJbQj/cT58myWVM9\n" +
                "bL0dJj7FoY0fgO9iDsHtAaNvsF3gq9Tz9pTNE1PYrAhrFDP/tw2JrruvoHXLyCbz\n" +
                "Tv/YlZk9raKUO4GtUgcGbBdrKEhzMzLkPpgsnjyyPwjdi2Umbmbs9trOQ5uL2ap+\n" +
                "A2FOma3WzswqJuVKeVIQx3O1\n" +
                "-----END CERTIFICATE-----";


        InputStream certStream = new ByteArrayInputStream(igorCertificate.getBytes(StandardCharsets.UTF_8));
        Map.Entry<PublicKey, String> keyLabel =  PemTools.loadCertKeyWithLabel(certStream);

        String label = keyLabel.getValue();

        assertEquals("\u017DAIKOVSKI,IGOR,37101010021", label);
    }
}
