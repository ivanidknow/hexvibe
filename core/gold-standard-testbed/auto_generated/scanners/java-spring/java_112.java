// Vulnerable: JAVA-112
public interface IBSidesService extends Remote {
   boolean registerTicket(String ticketID) throws RemoteException;
   void vistTalk(String talkname) throws RemoteException;
   void poke(Attendee attende) throws RemoteException;
}
