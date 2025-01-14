package ee.cyber.cdoc2.client.mobileid;

import static ee.cyber.cdoc2.util.IdCodeValidationUtil.getValidatedIdentityCode;
import static ee.sk.mid.MidInputUtil.getValidatedPhoneNumber;


/**
 * User data for Mobile-ID authentication request
 * @param phoneNumber user phone number
 * @param identityCode user national identity number
 */
public record MobileIdUserData(
    String phoneNumber,
    String identityCode
) {

    public MobileIdUserData(String phoneNumber, String identityCode) {
        this.phoneNumber = getValidatedPhoneNumber(phoneNumber);
        this.identityCode = getValidatedIdentityCode(identityCode);
    }

}
