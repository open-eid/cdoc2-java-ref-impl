package ee.cyber.cdoc20.crypto;


import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;


public class RsaTest {

    // openssl rsa -in rsa_priv.pem -outform PEM -pubout -out rsa_pub.pem
    @SuppressWarnings("checkstyle:OperatorWrap")
    static final String pubKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs18v09QVTnzSTRrFnVhk\n" +
            "xDWM2rSHOua2rPz60CVazfOk5Vv9Jo4Nq6Uzo3yWS4DZ+3JgO5iRntFeI0NWZGsP\n" +
            "GbMWGWKlb4OYlbK0gnBdwsi4LS6LnRx7CfYKxOicL5akXqDP2NCoytHFG8QePPE1\n" +
            "XAHC7pHyC+hEa7Hggol6sdbEWOK7WLCmIjmJ+gJx2O3bg433ad0LX6swvclGNbe0\n" +
            "z+YagmYsu4ChfwY9Be6oVRvQzFEHOKh+tEibyutdFJ9fioyMjjZtL6lEx5xKUJ18\n" +
            "d4efC9apvJ810wRkMDqwR203HEJrkRnBg9RtkVPNzOMl8eH6eUdS/oDW5eysnKbt\n" +
            "rwIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    // openssl genrsa -out rsa_priv.pem 2048
    @SuppressWarnings("checkstyle:OperatorWrap")
    static final String rsaKeyPem =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEogIBAAKCAQEAs18v09QVTnzSTRrFnVhkxDWM2rSHOua2rPz60CVazfOk5Vv9\n" +
            "Jo4Nq6Uzo3yWS4DZ+3JgO5iRntFeI0NWZGsPGbMWGWKlb4OYlbK0gnBdwsi4LS6L\n" +
            "nRx7CfYKxOicL5akXqDP2NCoytHFG8QePPE1XAHC7pHyC+hEa7Hggol6sdbEWOK7\n" +
            "WLCmIjmJ+gJx2O3bg433ad0LX6swvclGNbe0z+YagmYsu4ChfwY9Be6oVRvQzFEH\n" +
            "OKh+tEibyutdFJ9fioyMjjZtL6lEx5xKUJ18d4efC9apvJ810wRkMDqwR203HEJr\n" +
            "kRnBg9RtkVPNzOMl8eH6eUdS/oDW5eysnKbtrwIDAQABAoIBAD8N0QRH442Jt2u/\n" +
            "Y4RiVFnc8TzYhUkhXUoGTCzrVLZdVbQC2ES7Xvbdxf9MhpDYJMiNdmK8yUPpGYyP\n" +
            "2UjHkbFZEQWvdbRzsCm/flD0KyGT6ZqIaC+8mUvxH+wEURMxg2p4YVg4UX2qq/2M\n" +
            "vYxyxm0neVzgFRQ2fAbXqrJ4nZbx75KAU8Vepyn1zUHbyjwnaxly+rjiEkTujtrV\n" +
            "+/FjAwZQ/mnoS0GbMlX6DKfMm6+wJW0ZYZKoqkaCuMPMT+msn2x3DPVgbwm8OO/V\n" +
            "Qari5g8XwB+b9R5dWnli9dGyW9jFzQ/rhkgni0Z3hVc4lP/6WWbfxwRmAXFjIVyf\n" +
            "PeavBsECgYEA4N/aivOA3YLUVBlKojUf3deBM6FvPuvELfhSCNVfotIwSsT2krP4\n" +
            "NKR56PvbScNopdnaXgw1SrmWLZjEQy16cv8DL3a7o70HjSiHn15GZSqt1pBkBKuc\n" +
            "9fj7JhvWCyNIqcAguchSQS4gf1GrvgIQUvBahIo3vJbdkOpmnfO7QrECgYEAzDMB\n" +
            "OtgO/0PX5VGr9u7K9Fm7ER/fQym7L+pTigMgFUP15dfO4srbHzYyPyws+jOazDbF\n" +
            "huGeX8rQqdFJtRgkfVLFVK+taK6UFh4tspzFW1QTX+cIt2XVR9gb4Aq+8mbodb0c\n" +
            "feT70sOXqeaxrqqgwpdI20B04xALyQTUMQqbjl8CgYAZyhJqNRrmTIbFTlE84RLS\n" +
            "glCS90Sm1qsdCol98dqR9cEMEiKlGHaysto4WgoAH6T0wFNGzeeetkH+4LJBcgnE\n" +
            "/nIDE37ZfGhNTAShxlIUcByXqt+NmZDatL8406BsjpNaxGn8ZHjqeLvJXjhwBhSR\n" +
            "LndzE9bojfTDFd7G5pjnQQKBgFV2f2xGYzh5B5IFtaha1vyf1YhcQ5ATljF+rEoV\n" +
            "9saPtAnnYcJPzpfoke0YqxZopMAVqGREZ4mGFAEPA/9URGljTA2enUAz2OzM4qlf\n" +
            "rcYEkTtRMbe4WiSAkWIafUJsyZwFczhJrw/OJtrIH9OPvErVEHwbJRCndZdDex+v\n" +
            "Zd2XAoGAcA2ntZzUHM7K3A02pCPHtW6X2pmvgcNdQk2trI893mEPdFKPH+FPdaEa\n" +
            "hxr/6JxIBbP93XG7m0Na8g0SaSl+jJHQOe2Vii7SgCSI47mp2bECUEQXqw0gek+E\n" +
            "FpMKKtuLmE733CZbg85d9dCMU808+XR+psNvUR6XhxRB+lzgVjc=\n" +
            "-----END RSA PRIVATE KEY-----\n";


    @Test
    void testRsaOep() throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, SecureRandom.getInstanceStrong());

        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        String plainSecret = "_secret_"; // 8 bytes as FMK_LEN

        checkRsaEncryption(plainSecret, publicKey, privateKey);
    }

    static void checkRsaEncryption(String plainSecret, RSAPublicKey publicKey, RSAPrivateKey privateKey)
            throws Exception {
        byte[] data = plainSecret.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = Crypto.rsaEncrypt(data, publicKey);

        byte[] decryptedBytes = Crypto.rsaDecrypt(encrypted, privateKey);
        String decrypted =  new String(decryptedBytes, StandardCharsets.UTF_8);

        Assertions.assertEquals(plainSecret, decrypted);
    }

    @Test
    void testLoadRsaKeys() throws Exception {
        PublicKey publicKey = PemTools.loadPublicKey(pubKeyPem);
        KeyPair keyPair = PemTools.loadFromPem(rsaKeyPem);

        Assertions.assertEquals("RSA", keyPair.getPublic().getAlgorithm());
        Assertions.assertEquals(publicKey, keyPair.getPublic());

        checkRsaEncryption("secret", (RSAPublicKey) publicKey, (RSAPrivateKey) keyPair.getPrivate());
    }
}
