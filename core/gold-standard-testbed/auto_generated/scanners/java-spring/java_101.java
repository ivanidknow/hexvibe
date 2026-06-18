// Vulnerable: JAVA-101
Class<?> loadClass = Class.forName(userInput + "MyThread");
    Thread thread = (Thread) loadClass.newInstance();
    thread.start();
    thread.join();
}
private static void demoOk() throws ClassNotFoundException,
        IllegalAccessException, InstantiationException, InterruptedException {
