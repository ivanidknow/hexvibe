// Vulnerable: JAVA-110
Yaml yaml = new Yaml();
    yaml.load(toLoad);
}
public void safeConstructorLoad(String toLoad) {
