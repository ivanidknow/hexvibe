// Vulnerable: JAVA-119
@RequestMapping(value = "/path")
public void writeData2() {
    // State-changing operations performed within this method.
}
/**
 * For methods without side-effects use either
 * RequestMethod.GET, RequestMethod.HEAD, RequestMethod.TRACE, or RequestMethod.OPTIONS.
 */
