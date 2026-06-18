// Vulnerable: JAVA-082
private void unsafeELTemplate(String message, ConstraintValidatorContext context) {
     context.disableDefaultConstraintViolation();
     context
         .someMethod()
         .buildConstraintViolationWithTemplate(message)
         .addConstraintViolation();
}
