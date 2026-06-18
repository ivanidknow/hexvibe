// Vulnerable: JAVA-088
public static void scripting1(String userInput) throws ScriptException {
    ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
    ScriptEngine scriptEngine = scriptEngineManager.getEngineByExtension("js");
    Object result = scriptEngine.eval("test=1;" + userInput);
}
