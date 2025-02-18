package ee.cyber.cdoc2.cli.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ee.cyber.cdoc2.CDocDecrypter;
import ee.cyber.cdoc2.cli.DecryptionKeyExclusiveArgument;
import ee.cyber.cdoc2.container.CDocParseException;
import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.container.recipients.PBKDF2Recipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.crypto.PemTools;
import ee.cyber.cdoc2.crypto.Pkcs11Tools;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.crypto.jwt.InteractionParamsConfigurable;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledPassword;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;

import ee.cyber.cdoc2.services.Services;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.PKCS11_LIBRARY_PROPERTY;
import static ee.cyber.cdoc2.crypto.AuthenticationIdentifier.createSemanticsIdentifier;
import static ee.sk.mid.MidInputUtil.getValidatedPhoneNumber;


/**
 * Utility class for building {@link CDocDecrypter}.
 */
public final class CDocDecryptionHelper {

    private static final Logger log = LoggerFactory.getLogger(CDocDecryptionHelper.class);

    private CDocDecryptionHelper() { }

    /**
     * Loads DecryptionKeyMaterial from CLI options. If decryption material is not given by user, then
     * tries to load decryption key material from smart-card. Asks PIN interactively when using smart-card.
     * Reads pkcs11 library location from `pkcs11-library` Java system property if set. Otherwise, uses system default
     * location.
     * @param slot smart-card slot number when overwriting default
     * @param keyAlias key alias
     * @return loaded DecryptionKeyMaterial
     * @throws GeneralSecurityException general security exception
     * @throws IOException in case decryption key material extraction has failed
     */
    public static DecryptionKeyMaterial getSmartCardDecryptionKeyMaterial(
        Integer slot,
        String keyAlias
    ) throws GeneralSecurityException, IOException {
        log.info("Decryption key not provided as CLI parameter, trying to read it from smart-card");

        String pkcs11LibPath = System.getProperty(PKCS11_LIBRARY_PROPERTY, null);
        KeyPair keyPair =  Pkcs11Tools.loadFromPKCS11Interactively(pkcs11LibPath, slot, keyAlias);

        return DecryptionKeyMaterial.fromKeyPair(keyPair);
    }

    /**
     * Loads DecryptionKeyMaterial from CLI options.
     * @param cdocFile cdoc file that is decrypted. Used to find correct key label,
     *                 if password is entered without a label ":password"
     * @param decryptArguments exclusive decryption arguments. At least one of them must be present:
     *                     - labeledPasswordParam: when labeledPasswordParam.isEmpty() == true
     *                       (-pw without value), then password is read interactively. Has value
     *                       when password was provided from CLI
     *                     - secret: LabeledSecret value when provided, otherwise null
     *                     - p12: Read private key from .p12 file. Format is "FILE
     *                       .p12:password". null when not provided
     *                     - privKeyFile: file containing privateKey in PEM format.
     *                       null when not provided
     * @return loaded DecryptionKeyMaterial
     * @throws GeneralSecurityException general security exception
     * @throws IOException in case decryption key material extraction has failed
     * @throws CDocParseException in case decryption key material extraction has failed
     */
    public static DecryptionKeyMaterial getDecryptionKeyMaterial(
        File cdocFile,
        DecryptionKeyExclusiveArgument decryptArguments
    ) throws GeneralSecurityException, IOException, CDocParseException {
        Objects.requireNonNull(cdocFile);
        LabeledPasswordParam labeledPasswordParam = decryptArguments.getLabeledPasswordParam();
        LabeledSecret secret = decryptArguments.getSecret();
        String p12 = decryptArguments.getP12();
        File privKeyFile = decryptArguments.getPrivKeyFile();
        boolean isWithSid = decryptArguments.isWithSid();
        boolean isWithMid = decryptArguments.isWithMid();

        countParams(labeledPasswordParam, secret, p12, privKeyFile, isWithSid, isWithMid);

        DecryptionKeyMaterial decryptionKm = null;
        if (secret != null) {
            decryptionKm = DecryptionKeyMaterial.fromSecretKey(secret.getSecretKey(), secret.getLabel());
        }

        if (labeledPasswordParam != null) {
            decryptionKm = getPasswordDecryptionKeyMaterial(
                decryptionKm, cdocFile, labeledPasswordParam
            );
        }

        if (isWithSid && decryptionKm == null) {
            decryptionKm = getSidDecryptionKeyMaterial(decryptArguments.getSid(), cdocFile);
        }

        if (isWithMid && decryptionKm == null) {
            decryptionKm = getMidDecryptionKeyMaterial(
                decryptArguments.getMid(), decryptArguments.getMidPhone(), cdocFile
            );
        }

        // this must be final initialization
        if (decryptionKm == null)  {
            decryptionKm = getKeyPairDecryptionKeyMaterial(p12, privKeyFile);
        }

        return decryptionKm;
    }

    private static DecryptionKeyMaterial getSidDecryptionKeyMaterial(String idCode, File cdocFile) {
        AuthenticationIdentifier authIdentifier = AuthenticationIdentifier.forKeyShares(
            createSemanticsIdentifier(idCode), AuthenticationIdentifier.AuthenticationType.SID
        );

        DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromAuthMeans(authIdentifier);
        addInteractionParameters(cdocFile, dkm);
        return dkm;

    }

    /**
     *
     * @param idCode estonian national identity code
     * @param phoneNumber user phone number international format +372...
     * @param cdocFile cdoc2 file decrypted
     * @return
     */
    private static DecryptionKeyMaterial getMidDecryptionKeyMaterial(
        String idCode,
        String phoneNumber,
        File cdocFile
    ) {

        AuthenticationIdentifier authIdentifier = AuthenticationIdentifier.forMidDecryption(
            createSemanticsIdentifier(idCode),
            getValidatedPhoneNumber(phoneNumber)
        );

        DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromAuthMeans(authIdentifier);
        addInteractionParameters(cdocFile, dkm);
        return dkm;
    }

    private static void addInteractionParameters(File cdocFile, DecryptionKeyMaterial dkm) {
        if (dkm instanceof InteractionParamsConfigurable paramsConfigurable) {

            InteractionParams interactionParams = (cdocFile == null)
                ? InteractionParams.displayTextAndPin()
                : InteractionParams.displayTextAndVCCForDocument(cdocFile.toPath().getFileName().toString());
            interactionParams.addAuthListener(e -> System.out.println("Verification code:" + e.getVerificationCode()));
            paramsConfigurable.init(interactionParams);
        }
    }

    private static DecryptionKeyMaterial getPasswordDecryptionKeyMaterial(
        DecryptionKeyMaterial decryptionKm,
        File cdocFile,
        LabeledPasswordParam labeledPasswordParam
    ) throws IOException, GeneralSecurityException, CDocParseException {
        List<Recipient> recipients = Envelope.parseHeader(Files.newInputStream(cdocFile.toPath()));
        LabeledPassword labeledPassword = getLabeledPassword(labeledPasswordParam, recipients);

        if (labeledPassword != null) {
            decryptionKm = (decryptionKm == null)
                ? DecryptionKeyMaterial
                .fromPassword(labeledPassword.getPassword(), labeledPassword.getLabel())
                : decryptionKm;
        }

        return decryptionKm;
    }

    private static void countParams(
        LabeledPasswordParam labeledPasswordParam,
        LabeledSecret secret,
        String p12,
        File privKeyFile,
        boolean isWithSid,
        boolean isWithMid
    ) {
        int n = 0;
        if (labeledPasswordParam != null) n += 1;
        if (secret != null) n += 1;
        if (p12 != null) n += 1;
        if (privKeyFile != null) n += 1;
        if (isWithSid) n += 1;
        if (isWithMid) n += 1;

        if (n > 1) {
            //should be detected by picocli ArgGroup(exclusive = true) before reaching here
            throw new IllegalArgumentException("More than one decryption key provided");
        }
    }

    private static DecryptionKeyMaterial getKeyPairDecryptionKeyMaterial(
        String p12,
        File privKeyFile
    ) throws CDocParseException, GeneralSecurityException, IOException {
        KeyPair keyPair;
        if (p12 != null) {
            keyPair = PemTools.loadKeyPairFromP12File(p12);
        } else if (privKeyFile != null) {
            keyPair = PemTools.loadKeyPair(privKeyFile);
        } else {
            throw new CDocParseException(
                "At least one of decryption keys must be present"
            );
        }

        return DecryptionKeyMaterial.fromKeyPair(keyPair);
    }

    public static CDocDecrypter getDecrypterWithFilesExtraction(
        File cdocFile,
        String[] filesToExtract,
        File outputPath,
        DecryptionKeyMaterial decryptionKeyMaterial,
        @Nullable Services services
    ) throws IOException {
        return new CDocDecrypter()
            .withCDoc(cdocFile)
            .withRecipient(decryptionKeyMaterial)
            .withFilesToExtract(Arrays.asList(filesToExtract))
            .withServices(services)
            .withDestinationDirectory(outputPath);
    }

    public static List<Recipient> parseRecipients(File cdocFile)
        throws IOException, GeneralSecurityException, CDocParseException {

        return Envelope.parseHeader(Files.newInputStream(cdocFile.toPath()));
    }

    public static LabeledPassword readLabelAndPasswordInteractively(List<Recipient> recipients) {
        if (recipients.size() == 1) {
            return fillLabelFromRecipient(
                InteractiveCommunicationUtil.readOnlyPasswordInteractively(false),
                recipients
            );
        } else {
            return InteractiveCommunicationUtil.readPasswordAndLabelInteractively(false);
        }
    }

    /**
     * Get LabeledPassword from labeledPasswordParam and recipients.
     * When labeledPasswordParam.isEmpty() ask LabeledPassword interactively.
     * @param labeledPasswordParam provided from cli
     * @param recipients parsed from CDOC2 header
     * @return labeledParam or null when labeledPasswordParam was null
     */
    @Nullable
    public static LabeledPassword getLabeledPassword(
        @Nullable LabeledPasswordParam labeledPasswordParam,
        List<Recipient> recipients
    ) {
        LabeledPassword labeledPassword = null;
        if (labeledPasswordParam != null) {
            labeledPassword = (labeledPasswordParam.isEmpty())
                ? readLabelAndPasswordInteractively(recipients)
                : fillLabelFromRecipient(labeledPasswordParam.labeledPassword(), recipients);
        }

        return labeledPassword;
    }

    /**
     * When label was not provided and recipients contains only one recipient, then set labeledPassword
     * label value to recipient.label value
     * @param labeledPassword password with label
     * @param recipients recipients
     * @return LabeledPassword
     */
    private static LabeledPassword fillLabelFromRecipient(
        @Nonnull LabeledPassword labeledPassword,
        @Nonnull List<Recipient> recipients
    ) {
        Objects.requireNonNull(labeledPassword);
        Objects.requireNonNull(recipients);

        List<PBKDF2Recipient> pbkdf2Recipients = recipients.stream()
            .filter(PBKDF2Recipient.class::isInstance)
            .map(r -> (PBKDF2Recipient)r).toList();


        if (pbkdf2Recipients.size() == 1 && labeledPassword.getLabel().isEmpty()) {
            return new LabeledPassword() {
                @Override
                public String getLabel() {
                    return recipients.get(0).getRecipientKeyLabel();
                }

                @Override
                public char[] getPassword() {
                    return labeledPassword.getPassword();
                }
            };
        } else {
            return labeledPassword;
        }
    }

}
