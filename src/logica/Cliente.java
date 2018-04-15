package logica;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;


@SuppressWarnings("deprecation")
public class Cliente {
	private final String HOLA = "HOLA";
	private final String INICIO = "INICIO";
	private final String ALGORITMOS = "ALGORITMOS";
	private final String ESTADO = "ESTADO";
	private final String OK = "OK";
	private final String ERROR = "ERROR";
	private final String CERTCLNT = "CERTCLNT";
	private final String CERTSRV = "CERTSRV";
	private final String ACT1 = "ACT1";
	private final String ACT2 = "ACT2";
	private final String SEPARADOR = "SEPARADOR";
	private final String[] ALGS  = {"RSA"};
	
	private String posicion;
	private Socket socket;
	PrintWriter escritor;
	BufferedReader lector;
	
	public Cliente() {
		posicion = "41 24.2028, 2 10.4418";
		socket = new Socket();
		try {
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		} catch (IOException e) {}
	}
	
	public void ejecutar() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		String respuesta = "";
		escritor.print(HOLA);
		
		respuesta = lector.readLine();
		
		if (respuesta.equals(INICIO)) {
			String alg = ALGORITMOS;
			for (int i = 0; i < ALGS.length; i++) {
				alg += ":" + ALGS[i];
			}
		} else {
			System.out.println("ERROR: Mensaje erróneo del servidor: " + respuesta);
			return;
		}
		
		respuesta = lector.readLine();
		int tamanioBytes = 0;
		if (respuesta.equals(ESTADO + ":" + OK)) {
			escritor.println(CERTCLNT);

			try {
				java.security.cert.X509Certificate cert = certificado();
				byte[] myByte = cert.getEncoded(); 
				tamanioBytes = myByte.length;
				socket.getOutputStream().write(myByte);
				socket.getOutputStream().flush();
			} catch (Exception e) {} 
		} else if (respuesta.equals(ESTADO + ":" + ERROR)) {
			System.out.println("ERROR: El servidor no es compatible con los algoritmos de encriptación.");
			return;
		} else {
			System.out.println("ERROR: Mensaje erróneo del servidor: " + respuesta);
			return;
		}
		
		respuesta = lector.readLine();
		if (respuesta.equals(ESTADO + ":" + OK)) {
			respuesta = lector.readLine();
			byte[] certificadoSrv = new byte[tamanioBytes];
			if (respuesta.equals(CERTSRV)) {
				socket.getInputStream().read(certificadoSrv);
				//X509Certificate caCert =  certificadoSrv.;
				boolean todoBien = false;
				
				if (todoBien) {
					escritor.println(ESTADO + ":" + OK);
				} else {
					escritor.println(ESTADO + ":" + ERROR);
					System.out.println("Error: El certificado no es valido.");
					return;
				}
				byte[] l = new byte[256];
				socket.getInputStream().read(l);
				SecretKeySpec skc = new SecretKeySpec(l, "AES");
				Cipher ca = Cipher.getInstance("AES/CBC/PKCS7Padding");
				ca.init(Cipher.DECRYPT_MODE, skc);
				byte[] decryptedBytes = ca.doFinal(l);
				String decryptedString = new String(decryptedBytes);
			}
		} else if (respuesta.equals(ESTADO + ":" + ERROR)) {
			System.out.println("ERROR: El servidor envió ERROR como respuesta.");
			return;
		} else {
			System.out.println("ERROR: Mensaje erróneo del servidor: " + respuesta);
			return;
		}
		
		
		
		
		
	}

	private X509Certificate certificado() throws CertificateParsingException, CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
		Date startDate = new Date();                // time from which certificate is valid
		Date expiryDate = new Date();               // time after which certificate is not valid
		BigInteger serialNumber = BigInteger.TEN;       // serial number for certificate
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		PrivateKey caKey = generator.genKeyPair().getPrivate();              // private key of the certifying authority (ca) certificate
		X509Certificate caCert = new X509V3CertificateGenerator().generate(caKey);        // public key certificate of the certifying authority
		KeyPair keyPair = generator.genKeyPair();               // public/private key pair that we are creating certificate for
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal              subjectName = new X500Principal("CN=Test V3 Certificate");
		 
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(caCert.getSubjectX500Principal());
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(subjectName);
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("RSA");
		 
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(keyPair.getPublic().getEncoded() ));
		 
		X509Certificate cert = certGen.generate(caKey, "BC");   // note: private key of CA
		return null;
	}
}
