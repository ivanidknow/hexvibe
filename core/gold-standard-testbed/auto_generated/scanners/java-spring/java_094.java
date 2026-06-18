// Vulnerable: JAVA-094
GroupPeer.executeQuery(injection,"",false);
}
public void falsePositive(BasePeer peer0) {
    String constantValue = "SELECT * FROM test";
