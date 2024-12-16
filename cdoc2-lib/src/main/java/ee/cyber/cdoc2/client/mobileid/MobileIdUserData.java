package ee.cyber.cdoc2.client.mobileid;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Uuser data for Mobile-ID authentication request
 * @param phoneNumber user phone number
 * @param identityCode user national identity number
 */
public record MobileIdUserData(
    String phoneNumber,
    String identityCode
) {

    private static final String PHONE_NUMBER_PATTERN = "\\+37\\d{5,10}";
    private static final String IDENTITY_CODE_PATTERN = "\\d{11}";
    private static final Pattern phoneNrPpattern = Pattern.compile(PHONE_NUMBER_PATTERN);
    private static final Pattern idPattern = Pattern.compile(IDENTITY_CODE_PATTERN);

    public MobileIdUserData(String phoneNumber, String identityCode) {
        this.phoneNumber = validatePhoneNumber(phoneNumber);
        this.identityCode = validateIdentityCode(identityCode);
    }

    private String validatePhoneNumber(String phoneNr) {
        Matcher matcher = phoneNrPpattern.matcher(phoneNr);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid phone number: " + phoneNr);
        }

        return phoneNr;
    }

    private String validateIdentityCode(String idCode) {
        Matcher matcher = idPattern.matcher(idCode);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid identity number: " + idCode);
        }

        return idCode;
    }

}
