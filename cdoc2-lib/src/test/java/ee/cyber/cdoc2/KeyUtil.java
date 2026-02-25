package ee.cyber.cdoc2;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import ee.cyber.cdoc2.crypto.Crypto;
import ee.cyber.cdoc2.crypto.KeyAlgorithm;
import ee.cyber.cdoc2.crypto.PemTools;


public final class KeyUtil {

    @SuppressWarnings({"checkstyle:OperatorWrap", "squid:S6706"})
    private static final String BOB_KEY_PEM_EC384 = """
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDAFxoHAdX8mU9cjiXOy46Gljmongxto0nHwRQs5cb93vIcysAaYLmhL
        mH4DPqnSXJWgBwYFK4EEACKhZANiAAR5Yacpp5H4aBAIxkDtdBXcw/BFyMNEQu4B
        LqnEv1cUVHROnhw3hAW63F3H2PI93ZzB/BT6+C+gOLt3XkCT/H3C9X1ZktCd5lS2
        BmC8zN4UciwrTb68gt4ylKUCd5g30KY=
        -----END EC PRIVATE KEY-----
        """;

    @SuppressWarnings({"checkstyle:OperatorWrap", "squid:S6706"})
    private static final String BOB_KEY_PEM_EC256 = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIELeTkTT8cENlN9EBk0lEYpJ8YUO984+5Xqf0HEqAfWMoAoGCCqGSM49
        AwEHoUQDQgAEnfHV0tndYo3MjcPcw3KL6JxjoLO44deGTfBJ9CxhLRsctVJYX3y/
        N0snT9m9Y1AB/An9bD+rpDrVIeNIupEahg==
        -----END EC PRIVATE KEY-----
        """;

    private KeyUtil() { }

    public static KeyPairGenerator getKeyPairRsaInstance() throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(KeyAlgorithm.Algorithm.RSA.name());
    }

    public static KeyPair createKeyPairEc384() throws Exception {
        return PemTools.loadKeyPair(BOB_KEY_PEM_EC384);
    }

    public static KeyPair createKeyPairEc256() throws Exception {
        return PemTools.loadKeyPair(BOB_KEY_PEM_EC256);
    }

    public static PublicKey createPublicKey() throws Exception {
        return createKeyPairEc384().getPublic();
    }

    public static SecretKey createSecretKey() throws Exception {
        byte[] secret = new byte[Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES];
        SecureRandom.getInstanceStrong().nextBytes(secret);
        return new SecretKeySpec(secret, "");
    }

}
