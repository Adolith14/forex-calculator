package com.teamwork.forexcalculator.user.service.phoneNumberValidator;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;

public class PhoneNumberValidator {
    private static final PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();

    public static boolean isValid(String phoneNumber, String countryCode) {
        try {
            // Parse the number with country code context
            Phonenumber.PhoneNumber number = phoneUtil.parse(phoneNumber, countryCode);

            // Special handling for Tanzania numbers
            if ("TZ".equals(countryCode)) {
                return isValidTanzaniaNumber(number);
            }

            return phoneUtil.isValidNumber(number);
        } catch (NumberParseException e) {
            return false;
        }
    }

    private static boolean isValidTanzaniaNumber(Phonenumber.PhoneNumber number) {
        // Tanzania numbers must have country code +255 and 9-digit national number
        if (number.getCountryCode() != 255) return false;

        String nationalNumber = String.valueOf(number.getNationalNumber());
        return nationalNumber.matches("^[0-9]{9}$");
    }

    public static String formatE164(String phoneNumber, String countryCode)
            throws NumberParseException {
        Phonenumber.PhoneNumber number = phoneUtil.parse(phoneNumber, countryCode);
        return phoneUtil.format(number, PhoneNumberUtil.PhoneNumberFormat.E164);
    }
}