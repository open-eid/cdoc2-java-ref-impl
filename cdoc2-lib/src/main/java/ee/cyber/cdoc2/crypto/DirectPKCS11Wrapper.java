package ee.cyber.cdoc2.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Properties;
import ee.cyber.cdoc2.config.PropertiesLoader;
//CHECKSTYLE:OFF
import sun.security.pkcs11.wrapper.*;
import static sun.security.pkcs11.wrapper.CK_ATTRIBUTE.DECRYPT_TRUE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_SERIAL_SESSION;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS_OAEP;
//CHECKSTYLE:ON
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_CAPSULE_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.PKCS11_LIBRARY_PROPERTY;
import static ee.cyber.cdoc2.config.KeyCapsuleClientConfigurationProps.getSlotOrDefault;
import static ee.cyber.cdoc2.config.KeyCapsuleClientConfigurationProps.loadPkcs11LibPath;

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
 *   <li>Error handling is intentionally minimal; any PKCS#11 failure results in a {@link RuntimeException}.</li>
 * </ul>
 * <p>
 * The PKCS#11 library path, slot selection, and other parameters are resolved from
 * application configuration properties.
 */
public final class DirectPKCS11Wrapper {

    // PKCS#11 mechanism constants
    private static final long CKM_SHA256 = 0x00000250L;
    private static final long CKG_MGF1_SHA1 = 0x00000002L;
    private static final long CKZ_DATA_SPECIFIED = 0x00000001L;
    private static final long pSourceData = 0x00000000L;
    private static final long ulSourceDataLen = 0x00000000L;

    private DirectPKCS11Wrapper() {
    }

    public static byte[] rsaDecryptPKCS11(byte[] encrypted) {
        var properties = loadProperties();
        var slot = getSlotOrDefault(properties);
        var pkcs11LibraryPath = loadPkcs11LibPath(properties.getProperty(PKCS11_LIBRARY_PROPERTY, null));

        try {
            var p11 = PKCS11.getInstance(pkcs11LibraryPath, "C_GetFunctionList", null, false);
            var session = p11.C_OpenSession(slot, CKF_SERIAL_SESSION, null, null);

            p11.C_FindObjectsInit(session, new CK_ATTRIBUTE[]{DECRYPT_TRUE});
            var objects = p11.C_FindObjects(session, 100L);
            var hKey = objects[0];
            p11.C_FindObjectsFinal(session);

            byte[] decryptedBytes = decryptData(p11, session, hKey, encrypted);

            p11.C_CloseSession(session);
            return decryptedBytes;
        } catch (Exception e) {
            throw new RuntimeException("Decryption with PKCS11 failed", e);
        }
    }

    private static Properties loadProperties() {
        String propertiesFilePath = System.getProperty(KEY_CAPSULE_PROPERTIES);
        return PropertiesLoader.loadProperties(propertiesFilePath);
    }

    private static byte[] decryptData(
        PKCS11 p11,
        Long session,
        Long hKey,
        byte[] encryptedBytes
    ) throws PKCS11Exception {
        byte[] pParam = ByteBuffer.allocate(40)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(CKM_SHA256)
            .putLong(CKG_MGF1_SHA1)
            .putLong(CKZ_DATA_SPECIFIED)
            .putLong(pSourceData)
            .putLong(ulSourceDataLen)
            .array();

        CK_MECHANISM ckMechanism = new CK_MECHANISM(CKM_RSA_PKCS_OAEP, pParam);
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
}
