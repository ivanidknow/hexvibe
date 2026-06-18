// Vulnerable: JAVA-086
public void unsafeOgnlReflectionProvider3(String input, OgnlTextParser reflectionProvider) throws IntrospectionException, ReflectionException {
    reflectionProvider.evaluate( input );
}
