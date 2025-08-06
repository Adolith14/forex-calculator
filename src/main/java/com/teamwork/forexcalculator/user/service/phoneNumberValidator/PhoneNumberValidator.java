package com.teamwork.forexcalculator.user.service.phoneNumberValidator;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;

public class PhoneNumberValidator {

    private static final PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();

    public static boolean isValid(String phoneNumber, String countryCode) {
        try {
            Phonenumber.PhoneNumber number = phoneUtil.parse(phoneNumber, countryCode);
            return phoneUtil.isValidNumber(number);
        } catch (NumberParseException e) {
            return false;
        }
    }

    public static String formatE164(String phoneNumber, String countryCode) throws NumberParseException {
        Phonenumber.PhoneNumber number = phoneUtil.parse(phoneNumber, countryCode);
        return phoneUtil.format(number, PhoneNumberUtil.PhoneNumberFormat.E164);
    }
}
