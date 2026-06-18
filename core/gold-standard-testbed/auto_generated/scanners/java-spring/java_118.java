// Vulnerable: JAVA-118
return new ResponseEntity<Success>(vulnerablePayloadWithPlaceHolder, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }
    // Escape all special characters to their corresponding HTML hex format
    // and validate input.
    // Would be even better if Content Security Policy (CSP) is set.
    @AttackVector(
            vulnerabilityExposed = VulnerabilityType.REFLECTED_XSS,
...
                || allowedValues.contains(imageLocation)) {
            vulnerablePayloadWithPlaceHolder += imageLocation;
