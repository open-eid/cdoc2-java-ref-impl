package ee.cyber.cdoc2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import ee.cyber.cdoc2.util.PasswordValidationUtil;

import static org.junit.jupiter.api.Assertions.assertThrows;


class PasswordValidationTest {

    @Test
    void testStrongPassword() {
        PasswordValidationUtil.validatePassword("StrongPassword123456".toCharArray());
    }

    @Test
    void shouldAllowSpecialCharacter() {
        PasswordValidationUtil.validatePassword("Password_with_special_characters1!".toCharArray());
    }

    @Test
    void shouldAllowNumber() {
        PasswordValidationUtil.validatePassword("PasswordWithNumbers123".toCharArray());
    }

    @Test
    void shouldAllowWhitespace() {
        PasswordValidationUtil.validatePassword("Password With whitespaces1".toCharArray());
    }

    @Test
    void shouldFailPwValidationWithoutUpperCaseCharacter() {
        assertThrowsIllegalArgumentException(() ->
                PasswordValidationUtil.validatePassword("password_without_upper_case1".toCharArray())
            );
    }

    @Test
    void shouldFailPwValidationWithoutLowerCaseCharacter() {
        assertThrowsIllegalArgumentException(() ->
            PasswordValidationUtil.validatePassword("PASSWORD_WITHOUT_LOWER_CASE1".toCharArray())
        );
    }

    @Test
    void shouldFailPwValidationWithoutDigit() {
        assertThrowsIllegalArgumentException(() ->
            PasswordValidationUtil.validatePassword("PasswordWithoutAnyDigitInIt".toCharArray())
        );
    }

    @Test
    void shouldFailTooShortPwValidation() {
        assertThrowsIllegalArgumentException(() ->
            PasswordValidationUtil.validatePassword("Short1".toCharArray())
        );
    }

    @Test
    void shouldFailTooLongPwValidation() {
        String password = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!VeryLongPasswordIsNotAllowed"
            + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        assertThrowsIllegalArgumentException(() ->
            PasswordValidationUtil.validatePassword(password.toCharArray())
        );
    }

    private void assertThrowsIllegalArgumentException(Executable validation) {
        assertThrows(IllegalArgumentException.class, validation);
    }

}
