package ee.cyber.cdoc2.crypto;

import java.util.Arrays;
import ee.cyber.cdoc2.config.PropertiesLoader;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import javax.annotation.Nullable;
//CHECKSTYLE:OFF
import sun.security.pkcs11.wrapper.*;
import static sun.security.pkcs11.wrapper.CK_ATTRIBUTE.DECRYPT_TRUE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_SERIAL_SESSION;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS_OAEP;
//CHECKSTYLE:ON
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_CAPSULE_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.PKCS11_LIBRARY_PROPERTY;

/**
 * Utility class for performing RSA OAEP decryption via a direct PKCS#11 wrapper.
 * <p>
 * This class bypasses the standard Java Cryptography Architecture (JCA) PKCS#11
 * provider and instead uses {@code sun.security.pkcs11.wrapper} directly in order
 * to support RSA decryption with OAEP padding.
 * <p>
 * The built-in Java PKCS#11 provider does not support OAEP padding.
 * To work around this limitation, this class manually constructs the
 * {@link sun.security.pkcs11.wrapper.CK_MECHANISM} structure and invokes the
 * low-level PKCS#11 API.
 * <p>
 * <strong>Important notes:</strong>
 * <ul>
 *   <li>This class relies on internal JDK APIs ({@code sun.security.pkcs11.wrapper.*})
 *   that are not part of the Java SE specification.</li>
 *   <li>These APIs may change or be removed without notice in future Java versions.</li>
 *   <li>Use of this class requirers additional JVM flags (for example {@code --add-exports}).</li>
 * </ul>
 * <p>
 * The PKCS#11 library path, slot selection, and other parameters are resolved from system and
 * application configuration properties.
 */
public final class DirectPKCS11Wrapper {

    // PKCS#11 mechanism constants
    private static final long CKM_SHA256 = 0x00000250L;
    private static final long CKG_MGF1_SHA1 = 0x00000002L;
    private static final long CKZ_DATA_SPECIFIED = 0x00000001L;

    private DirectPKCS11Wrapper() {
    }

    /**
     * Decrypts the data using RSA OAEP padding.
     *
     * @param encrypted the encrypted bytes
     * @param slot token slot number
     * @param alias (optional) key alias, must be present if multiple keys are on the token
     * @return decrypted bytes
     */
    public static byte[] rsaDecryptPKCS11(
        byte[] encrypted,
        Integer slot,
        @Nullable String alias
    ) {
        var pkcs11LibraryPath = getPkcs11LibraryPath();
        PKCS11 p11 = null;
        Long session = null;

        try {
            p11 = PKCS11.getInstance(pkcs11LibraryPath, "C_GetFunctionList", null, false);
            session = p11.C_OpenSession(slot, CKF_SERIAL_SESSION, null, null);

            long hKey = alias == null ? getKey(p11, session) : getKeyWithAlias(p11, session, alias);

            byte[] decryptedBytes = decryptData(p11, session, hKey, encrypted);

            p11.C_CloseSession(session);
            return decryptedBytes;
        } catch (Exception e) {
            if (p11 != null && session != null) {
                try {
                    p11.C_CloseSession(session);
                } catch (PKCS11Exception sCloseException) {
                    e.addSuppressed(sCloseException);
                }
            }
            throw new RuntimeException("Decryption with PKCS11 failed", e);
        }
    }

    private static String getPkcs11LibraryPath() {
        // try to load from System Properties (initialized using -D)
        String pkcs11Library = System.getProperty(PKCS11_LIBRARY_PROPERTY);
        if (pkcs11Library != null) {
            return pkcs11Library;
        }

        // try loading from properties file
        try {
            String propertiesFilePath = System.getProperty(KEY_CAPSULE_PROPERTIES);
            var properties = PropertiesLoader.loadProperties(propertiesFilePath);
            return properties.getProperty(PKCS11_LIBRARY_PROPERTY, null);
        } catch (ConfigurationLoadingException e) {
            throw new ConfigurationLoadingException(
                "If the system property " + PKCS11_LIBRARY_PROPERTY + " is not set, "
                    + "a properties file must be provided.",
                e
            );
        }
    }

    private static byte[] decryptData(
        PKCS11 p11,
        Long session,
        Long hKey,
        byte[] encryptedBytes
    ) throws PKCS11Exception {
        CK_RSA_PKCS_OAEP_PARAMS params = new CK_RSA_PKCS_OAEP_PARAMS();
        params.hashAlg = CKM_SHA256;
        params.mgf = CKG_MGF1_SHA1;
        params.source = CKZ_DATA_SPECIFIED;
        params.pSourceData = null;

        // Create mechanism and set the parameter object directly
        CK_MECHANISM ckMechanism = new CK_MECHANISM(CKM_RSA_PKCS_OAEP);
        ckMechanism.pParameter = params;

        p11.C_DecryptInit(session, ckMechanism, hKey);

        byte[] decryptedBytes = new byte[encryptedBytes.length];

        var n = p11.C_Decrypt(
            session,
            0,
            encryptedBytes,
            0,
            encryptedBytes.length,
            0,
            decryptedBytes,
            0,
            encryptedBytes.length
        );

        return Arrays.copyOf(decryptedBytes, n);
    }

    private static long getKey(
        PKCS11 p11,
        long session
    ) throws PKCS11Exception {
        p11.C_FindObjectsInit(session, new CK_ATTRIBUTE[]{DECRYPT_TRUE});
        var objects = p11.C_FindObjects(session, 100L);
        p11.C_FindObjectsFinal(session);

        if (objects.length == 0) {
            throw new RuntimeException("No decryptable key objects found on the token.");
        }
        if (objects.length > 1) {
            throw new RuntimeException(
                "Multiple key objects on the token. "
                    + "Please specify an alias to select the correct key."
            );
        }

        return objects[0];
    }

    private static long getKeyWithAlias(
        PKCS11 p11,
        long session,
        String alias
    ) throws PKCS11Exception {
        // find the certificate by its label (what KeyStore shows as alias)
        p11.C_FindObjectsInit(session, new CK_ATTRIBUTE[]{
            new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_CERTIFICATE),
            new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, alias.toCharArray())
        });
        var certObjects = p11.C_FindObjects(session, 10L);
        p11.C_FindObjectsFinal(session);

        if (certObjects.length == 0) {
            throw new RuntimeException("No certificate found with alias: " + alias);
        }

        // read CKA_ID from the certificate
        CK_ATTRIBUTE[] idAttr = new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(PKCS11Constants.CKA_ID)};
        p11.C_GetAttributeValue(session, certObjects[0], idAttr);
        byte[] ckaId = (byte[]) idAttr[0].pValue;

        // find the private key with the same CKA_ID
        p11.C_FindObjectsInit(session, new CK_ATTRIBUTE[]{
            new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PRIVATE_KEY),
            new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, ckaId)
        });
        var keyObjects = p11.C_FindObjects(session, 10L);
        p11.C_FindObjectsFinal(session);

        if (keyObjects.length == 0) {
            throw new RuntimeException("No private key found matching certificate alias: " + alias);
        }

        return keyObjects[0];
    }
}
