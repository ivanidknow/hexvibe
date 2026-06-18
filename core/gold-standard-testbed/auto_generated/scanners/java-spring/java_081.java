// Vulnerable: JAVA-081
groovyLoader.parseClass(script,"test.groovy");
String hardcodedScript = "test.groovy";
