package ee.cyber.cdoc20.container;

import static org.junit.jupiter.api.Assertions.*;

import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.CipherInputStream;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.List;

class EnvelopeTest {
    private static final Logger log = LoggerFactory.getLogger(EnvelopeTest.class);

    byte[] fmkBuf =  new byte[Crypto.FMK_LEN_BYTES];

//    KeyPair recipientKeyPair = Crypto.generateEcKeyPair();
//    String recipientPubKeyB64 = Base64.getEncoder().encodeToString(recipientKeyPair.getPublic().getEncoded());
//    String recipientPrivKeyB64 = Base64.getEncoder().encodeToString(recipientKeyPair.getPrivate().getEncoded());
//    public static final String recipientPubKeyBase64 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGTr5ojK7f6VnWa2MNceu+BfBnhnejGBpqgi3cKxXxl3huGbBzDCku+/HwYw6R+EqVFHRuVGgspX/QwGzJqxxsxKCEOic3U4hNo4vChF3wMSlTbI2IypZeNdoJybzKXv7";
//    public static final String recipientPrivKeyBase64 = "ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDCFkOQ2qBEWDXFMKwR65pAI1I3Hsao+FBj0jroy0xgMl0W5qrGU9ULnGWGg6l0D3S8=";
// How to decode pub key from X.509 and priv key from PKCS#8 ?

    //https://stackoverflow.com/questions/41927859/how-do-i-load-an-elliptic-curve-pem-encoded-private-key
    //https://stackoverflow.com/questions/40434317/how-to-load-pem-encoded-elliptic-curve-public-keys-into-bouncy-castle/40439081#40439081
    //https://www.baeldung.com/java-read-pem-file-keys

    //ECPublicKey recipientPubKey;
    KeyPair recipientKeyPair;
    KeyPair senderKeyPair;

    @BeforeEach
    void initInputData() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        fmkBuf[0] = 'f';
        fmkBuf[1] = 'm';
        fmkBuf[2] = 'k';
        fmkBuf[fmkBuf.length - 1] = (byte)0xff;

        this.recipientKeyPair = ECKeys.generateEcKeyPair();

        this.senderKeyPair = ECKeys.generateEcKeyPair();
        //this.recipientPubKey = (ECPublicKey) recipientKeyPair.getPublic();

//        String recipientPubKeyB64 = Base64.getEncoder().encodeToString(recipientKeyPair.getPublic().getEncoded());
//        String recipientPrivKeyB64 = Base64.getEncoder().encodeToString(recipientKeyPair.getPrivate().getEncoded());
//
//        String senderPubKeyB64 = Base64.getEncoder().encodeToString(senderKeyPair.getPublic().getEncoded());
//        String senderPrivKeyB64 = Base64.getEncoder().encodeToString(senderKeyPair.getPrivate().getEncoded());


        //generate new keys for now as no idea how to decode keys from default encoding (X.509 and PKCS#8)


    }

    // Mainly flatbuffers and friends
    @Test
    void testHeaderSerializationParse() throws IOException, GeneralSecurityException, CDocParseException {

        ECPublicKey recipientPubKey = (ECPublicKey) recipientKeyPair.getPublic();
        InputStream payload = new ByteArrayInputStream("payload".getBytes(StandardCharsets.UTF_8));
        List<ECPublicKey> recipients = List.of((ECPublicKey) recipientKeyPair.getPublic());

        Envelope envelope = Envelope.prepare(fmkBuf, senderKeyPair, recipients);

        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(payload, dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);

        ByteArrayOutputStream headerOs = new ByteArrayOutputStream();
        List<Details.EccRecipient> details = Envelope.parseHeader(new ByteArrayInputStream(resultBytes), headerOs); //no exception is good for now

        assertTrue(details.size() == 1);

        assertEquals(recipientPubKey, details.get(0).getRecipientPubKey());
        assertEquals(senderKeyPair.getPublic(), details.get(0).getSenderPubKey());


    }

//    @Test
//    void testEnvelope() throws IOException, GeneralSecurityException, CDocParseException {
//
//        KeyPair aliceKeyPair = Crypto.generateEcKeyPair();
//        KeyPair bobKeyPair = Crypto.generateEcKeyPair();
//
//        InputStream payload = new ByteArrayInputStream("payload".getBytes(StandardCharsets.UTF_8));
//        ECPublicKey recipientPubKey = (ECPublicKey) bobKeyPair.getPublic();
//        List<ECPublicKey> recipients = List.of(recipientPubKey);
//
//        Envelope senderEnvelope = Envelope.build(fmkBuf, aliceKeyPair, recipients);
//        ByteArrayOutputStream dst = new ByteArrayOutputStream();
//        senderEnvelope.encrypt(payload, dst);
//        byte[] resultBytes = dst.toByteArray();
//
//        assertTrue(resultBytes.length > 0);
//
//        ByteArrayInputStream bis = new ByteArrayInputStream(resultBytes);
//        Envelope recipientEnvelope = Envelope.fromInputStream(bis, bobKeyPair);
//
//        assertEquals(senderEnvelope, recipientEnvelope);
//    }

    @Test
    void testContainer() throws IOException, GeneralSecurityException, CDocParseException {

        KeyPair aliceKeyPair = ECKeys.generateEcKeyPair();
        KeyPair bobKeyPair = ECKeys.generateEcKeyPair();

        InputStream payload = new ByteArrayInputStream("payload".getBytes(StandardCharsets.UTF_8));
        ECPublicKey recipientPubKey = (ECPublicKey) bobKeyPair.getPublic();
        List<ECPublicKey> recipients = List.of(recipientPubKey);

        Envelope senderEnvelope = Envelope.prepare(fmkBuf, aliceKeyPair, recipients);
        try (ByteArrayOutputStream dst = new ByteArrayOutputStream()) {
            senderEnvelope.encrypt(payload, dst);
            byte[] cdocContainerBytes = dst.toByteArray();

            assertTrue(cdocContainerBytes.length > 0);

            try (ByteArrayInputStream bis = new ByteArrayInputStream(cdocContainerBytes);
                 CipherInputStream cis = Envelope.decrypt(bis, bobKeyPair)) {

                byte[] buf = new byte[1024];
                int read = cis.read(buf);
                assertTrue(read > 0);
                String decrypted = new String(buf, 0, read, StandardCharsets.UTF_8);

                assertEquals("payload", decrypted);
            }
        }
    }



//FIXME: Random EnvelopeTest failure 22.03.22
//    [INFO] Running ee.cyber.cdoc20.container.EnvelopeTest
//[main] DEBUG ee.cyber.cdoc20.container.Envelope - encrypted FMK: e5f5a4ed70ad86d18b0c7954c393d34ec585d4d6944b38acdea50a5ca85e6302
//[main] DEBUG ee.cyber.cdoc20.container.Envelope - Parsed encrypted FMK: e5f5a4ed70ad86d18b0c7954c393d34ec585d4d6944b38acdea50a5ca85e6302
//[main] DEBUG ee.cyber.cdoc20.crypto.Crypto - decoded X 009739f29fffbf0ed545dbda8c9bb3da111cc70747e3260739135caaa3b938337516538c4a8d6606596d4a59620749b76d
//[main] DEBUG ee.cyber.cdoc20.crypto.Crypto - decoded Y 00a72aa90a2f0706dc542eea3d79204df7f4a11c21e455d9c5fdb2c609d3c98097c76121dd7b9b366dd691ab9f190808c1
//[main] ERROR ee.cyber.cdoc20.crypto.Crypto - Invalid pubKey len 96, expected 48, encoded: 04c1c26fb6d2486cf09894f08441a660b4b97289fa6f87d3bae9ad22dbe7f2b2bab8a630fde92e582b612037c0894f8b169c911a05056890cf7b7da20b96f58328bd1c603f355273c1cfbc9f1b415f8ea63da725d6192ab1a13b544e6184ff71
//[ERROR] Tests run: 1, Failures: 0, Errors: 1, Skipped: 0, Time elapsed: 0.178 s <<< FAILURE! - in ee.cyber.cdoc20.container.EnvelopeTest
//[ERROR] testHeaderSerializationParse  Time elapsed: 0.164 s  <<< ERROR!
//    ee.cyber.cdoc20.container.CDocParseException: illegal EC pub key encoding
//    at ee.cyber.cdoc20.container.Envelope.parseHeader(Envelope.java:144)
//    at ee.cyber.cdoc20.container.EnvelopeTest.testHeaderSerializationParse(EnvelopeTest.java:80)
//    at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
//    at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:77)
//    at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
//    at java.base/java.lang.reflect.Method.invoke(Method.java:568)
//    at org.junit.platform.commons.util.ReflectionUtils.invokeMethod(ReflectionUtils.java:725)
//    at org.junit.jupiter.engine.execution.MethodInvocation.proceed(MethodInvocation.java:60)
//    at org.junit.jupiter.engine.execution.InvocationInterceptorChain$ValidatingInvocation.proceed(InvocationInterceptorChain.java:131)
//    at org.junit.jupiter.engine.extension.TimeoutExtension.intercept(TimeoutExtension.java:149)
//    at org.junit.jupiter.engine.extension.TimeoutExtension.interceptTestableMethod(TimeoutExtension.java:140)
//    at org.junit.jupiter.engine.extension.TimeoutExtension.interceptTestMethod(TimeoutExtension.java:84)
//    at org.junit.jupiter.engine.execution.ExecutableInvoker$ReflectiveInterceptorCall.lambda$ofVoidMethod$0(ExecutableInvoker.java:115)
//    at org.junit.jupiter.engine.execution.ExecutableInvoker.lambda$invoke$0(ExecutableInvoker.java:105)
//    at org.junit.jupiter.engine.execution.InvocationInterceptorChain$InterceptedInvocation.proceed(InvocationInterceptorChain.java:106)
//    at org.junit.jupiter.engine.execution.InvocationInterceptorChain.proceed(InvocationInterceptorChain.java:64)
//    at org.junit.jupiter.engine.execution.InvocationInterceptorChain.chainAndInvoke(InvocationInterceptorChain.java:45)
//    at org.junit.jupiter.engine.execution.InvocationInterceptorChain.invoke(InvocationInterceptorChain.java:37)
//    at org.junit.jupiter.engine.execution.ExecutableInvoker.invoke(ExecutableInvoker.java:104)
//    at org.junit.jupiter.engine.execution.ExecutableInvoker.invoke(ExecutableInvoker.java:98)
//    at org.junit.jupiter.engine.descriptor.TestMethodTestDescriptor.lambda$invokeTestMethod$7(TestMethodTestDescriptor.java:214)
//    at org.junit.platform.engine.support.hierarchical.ThrowableCollector.execute(ThrowableCollector.java:73)
//    at org.junit.jupiter.engine.descriptor.TestMethodTestDescriptor.invokeTestMethod(TestMethodTestDescriptor.java:210)
//    at org.junit.jupiter.engine.descriptor.TestMethodTestDescriptor.execute(TestMethodTestDescriptor.java:135)
//    at org.junit.jupiter.engine.descriptor.TestMethodTestDescriptor.execute(TestMethodTestDescriptor.java:66)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$6(NodeTestTask.java:151)
//    at org.junit.platform.engine.support.hierarchical.ThrowableCollector.execute(ThrowableCollector.java:73)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$8(NodeTestTask.java:141)
//    at org.junit.platform.engine.support.hierarchical.Node.around(Node.java:137)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$9(NodeTestTask.java:139)
//    at org.junit.platform.engine.support.hierarchical.ThrowableCollector.execute(ThrowableCollector.java:73)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.executeRecursively(NodeTestTask.java:138)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.execute(NodeTestTask.java:95)
//    at java.base/java.util.ArrayList.forEach(ArrayList.java:1511)
//    at org.junit.platform.engine.support.hierarchical.SameThreadHierarchicalTestExecutorService.invokeAll(SameThreadHierarchicalTestExecutorService.java:41)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$6(NodeTestTask.java:155)
//    at org.junit.platform.engine.support.hierarchical.ThrowableCollector.execute(ThrowableCollector.java:73)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$8(NodeTestTask.java:141)
//    at org.junit.platform.engine.support.hierarchical.Node.around(Node.java:137)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$9(NodeTestTask.java:139)
//    at org.junit.platform.engine.support.hierarchical.ThrowableCollector.execute(ThrowableCollector.java:73)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.executeRecursively(NodeTestTask.java:138)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.execute(NodeTestTask.java:95)
//    at java.base/java.util.ArrayList.forEach(ArrayList.java:1511)
//    at org.junit.platform.engine.support.hierarchical.SameThreadHierarchicalTestExecutorService.invokeAll(SameThreadHierarchicalTestExecutorService.java:41)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$6(NodeTestTask.java:155)
//    at org.junit.platform.engine.support.hierarchical.ThrowableCollector.execute(ThrowableCollector.java:73)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$8(NodeTestTask.java:141)
//    at org.junit.platform.engine.support.hierarchical.Node.around(Node.java:137)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.lambda$executeRecursively$9(NodeTestTask.java:139)
//    at org.junit.platform.engine.support.hierarchical.ThrowableCollector.execute(ThrowableCollector.java:73)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.executeRecursively(NodeTestTask.java:138)
//    at org.junit.platform.engine.support.hierarchical.NodeTestTask.execute(NodeTestTask.java:95)
//    at org.junit.platform.engine.support.hierarchical.SameThreadHierarchicalTestExecutorService.submit(SameThreadHierarchicalTestExecutorService.java:35)
//    at org.junit.platform.engine.support.hierarchical.HierarchicalTestExecutor.execute(HierarchicalTestExecutor.java:57)
//    at org.junit.platform.engine.support.hierarchical.HierarchicalTestEngine.execute(HierarchicalTestEngine.java:54)
//    at org.junit.platform.launcher.core.DefaultLauncher.execute(DefaultLauncher.java:170)
//    at org.junit.platform.launcher.core.DefaultLauncher.execute(DefaultLauncher.java:154)
//    at org.junit.platform.launcher.core.DefaultLauncher.execute(DefaultLauncher.java:90)
//    at org.apache.maven.surefire.junitplatform.JUnitPlatformProvider.invokeAllTests(JUnitPlatformProvider.java:142)
//    at org.apache.maven.surefire.junitplatform.JUnitPlatformProvider.invoke(JUnitPlatformProvider.java:117)
//    at org.apache.maven.surefire.booter.ForkedBooter.invokeProviderInSameClassLoader(ForkedBooter.java:383)
//    at org.apache.maven.surefire.booter.ForkedBooter.runSuitesInProcess(ForkedBooter.java:344)
//    at org.apache.maven.surefire.booter.ForkedBooter.execute(ForkedBooter.java:125)
//    at org.apache.maven.surefire.booter.ForkedBooter.main(ForkedBooter.java:417)
//    Caused by: java.lang.IllegalArgumentException: Incorrect length for uncompressed encoding
//    at ee.cyber.cdoc20.crypto.Crypto.decodeEcPublicKeyFromTls(Crypto.java:138)
//    at ee.cyber.cdoc20.crypto.Crypto.decodeEcPublicKeyFromTls(Crypto.java:161)
//    at ee.cyber.cdoc20.container.Envelope.parseHeader(Envelope.java:139)
//            ... 64 more



}