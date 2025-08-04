//package com.teamwork.forexcalculator.user.dto;
//
//import jakarta.validation.ConstraintValidator;
//import jakarta.validation.ConstraintValidatorContext;
//
//public class PasswordMatchesValidator implements ConstraintValidator<PasswordMatches, ResetPasswordDTO> {
//
//    @Override
//    public boolean isValid(ResetPasswordDTO resetPasswordDTO, ConstraintValidatorContext constraintValidatorContext) {
//        if (resetPasswordDTO.getNewPassword() == null || resetPasswordDTO.getConfirmPassword() == null) {
//            return false;
//        }
//        return resetPasswordDTO.getNewPassword().equals(resetPasswordDTO.getConfirmPassword());
//    }
//}
