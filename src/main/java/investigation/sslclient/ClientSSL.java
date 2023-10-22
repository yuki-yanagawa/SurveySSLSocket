package investigation.sslclient;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.cert.X509Certificate;

public class ClientSSL extends Thread implements HandshakeCompletedListener {
	private SSLSocket socket_;
	public ClientSSL() throws Exception {
		setting();
	}
	
	private void setting() throws Exception {
		FileInputStream fis = new FileInputStream("certdirforclient/ca.p12");
		KeyStore trustStore = KeyStore.getInstance("pkcs12");
		trustStore.load(fis, "CATEST".toCharArray());
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(trustStore);
		
		FileInputStream fis2 = new FileInputStream("certdirforclient/client.p12");
		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		keyStore.load(fis2, "CLIPASSWORD".toCharArray());
		
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, "CLIPASSWORD".toCharArray());
		
		SSLContext sc = SSLContext.getInstance("TLS");
		sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		
		SSLSocketFactory sf = sc.getSocketFactory();
		socket_ = (SSLSocket)sf.createSocket();
		socket_.addHandshakeCompletedListener(this);
		
	}

	@Override
	public void run() {
		connect();
	}
	
	private void connect() {
		try {
			socket_.connect(new InetSocketAddress("localhost", 9999));
			socket_.startHandshake();
		} catch(IOException e) {
			e.printStackTrace();
		}
	}

	public void handshakeCompleted(HandshakeCompletedEvent event) {
		try {
			SSLSession session = socket_.getSession();
			//クライアントサーバ間で決定した暗号の確認
			System.out.println(session.getCipherSuite());
			//サーバから送られてきた証明書を確認します
			X509Certificate[] x509Certificates = session.getPeerCertificateChain();
			for(X509Certificate x509Certificate : x509Certificates) {
				System.out.println(x509Certificate);
				System.out.println(x509Certificate.getSubjectDN().getName());
			}
			PublicKey publicKey = x509Certificates[0].getPublicKey();
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			OutputStream os = socket_.getOutputStream();
			os.write(cipher.doFinal("connection OK From Client!!!".getBytes()));
			os.flush();
			os.close();
			socket_.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
