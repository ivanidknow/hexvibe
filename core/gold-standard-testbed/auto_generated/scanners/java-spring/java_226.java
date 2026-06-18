// Vulnerable: JAVA-226
pingSocket = new Socket(servername, 23);
        out = new PrintWriter(pingSocket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(pingSocket.getInputStream()));
            out.println("ping");
            System.out.println(in.readLine());
            out.close();
            in.close();
            pingSocket.close();
    }
}
class Ok {
    public void oksocket1() {
