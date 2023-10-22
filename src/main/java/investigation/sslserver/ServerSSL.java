package investigation.sslserver;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class ServerSSL extends Thread {
	private SSLServerSocket svrSock_;
	public ServerSSL() throws Exception {
		setting();
	}
	private void setting() throws Exception {
		FileInputStream fis = new FileInputStream("certdirforserver/server.p12");
		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		keyStore.load(fis, "SVRPASSWORD".toCharArray());
		
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, "SVRPASSWORD".toCharArray());
		
		FileInputStream fis2 = new FileInputStream("certdirforserver/ca2.p12");
		KeyStore trustStore = KeyStore.getInstance("pkcs12");
		trustStore.load(fis2, "CA2PASSWORD".toCharArray());
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(trustStore);
		
		SSLContext sc = SSLContext.getInstance("TLS");
		sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		
		SSLServerSocketFactory ssf = sc.getServerSocketFactory();
		svrSock_ = (SSLServerSocket)ssf.createServerSocket(9999);
		svrSock_.setNeedClientAuth(true);
	}
	@Override
	public void run() {
		accept();
	}
	
	private void accept() {
		try {
			while(true) {
				SSLSocket socket = (SSLSocket)svrSock_.accept();
				try {
					byte[] buf = new byte[256];
					InputStream is = socket.getInputStream();
					is.read(buf);

					FileInputStream fiskey = new FileInputStream("certdirforserver/server.pk8");
					byte[] bufkey = new byte[2048];
					fiskey.read(bufkey);
					PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bufkey);
					KeyFactory kf = KeyFactory.getInstance("RSA");
					PrivateKey privateKey = kf.generatePrivate(keySpec);
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.DECRYPT_MODE, privateKey);
					byte[] data = cipher.doFinal(buf);
					
					
					System.out.println(new String(data));
					is.close();
					socket.close();
				} catch(IOException e) {
					e.printStackTrace();
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
