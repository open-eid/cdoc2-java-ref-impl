package ee.cyber.cdoc2.client.mobileid;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static ee.cyber.cdoc2.util.IdCodeValidationUtil.getValidatedIdentityCode;


/**
 * User data for Mobile-ID authentication request
 * @param phoneNumber user phone number
 * @param identityCode user national identity number
 */
public record MobileIdUserData(
    String phoneNumber,
    String identityCode
) {

    private static final String PHONE_NUMBER_PATTERN = "\\+37\\d{5,10}";
    private static final Pattern phoneNrPpattern = Pattern.compile(PHONE_NUMBER_PATTERN);

    public MobileIdUserData(String phoneNumber, String identityCode) {
        this.phoneNumber = getValidatedPhoneNumber(phoneNumber);
        this.identityCode = getValidatedIdentityCode(identityCode);
    }

    private String getValidatedPhoneNumber(String phoneNr) {
        Matcher matcher = phoneNrPpattern.matcher(phoneNr);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid phone number: " + phoneNr);
        }

        return phoneNr;
    }

}
