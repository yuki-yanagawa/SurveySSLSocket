package investigation;

import investigation.sslclient.ClientSSL;
import investigation.sslserver.ServerSSL;

public class Main {
	public static void main(String[] args) {
		try {
			ServerSSL server = new ServerSSL();
			server.start();
			Thread.sleep(1000);
			ClientSSL client = new ClientSSL();
			client.start();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}

