package logica;

import java.awt.FontFormatException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


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
	private final String[] ALGS  = {"AES", "RSA", "HMACMD5"};
	
	private String posicion;
	private Socket socket;
	PrintWriter escritor;
	BufferedReader lector;
	private PrivateKey llavePrivada;
	private X509Certificate certificadoServidor;
	
	private int id;
	
	public Cliente(int id) throws UnknownHostException, IOException {
		posicion = "41 24.2028, 2 10.4418";
		socket = new Socket("172.24.42.88", 4321);
		this.id=id;
		
		try {
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		} catch (IOException e) {}
	}
	
	public void ejecutar() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IllegalStateException, SignatureException, NoSuchProviderException, CertificateException {
		File file = new File("./data/datos.csv");
		PrintWriter csv = new PrintWriter(new FileWriter(file, true));
		//csv.println("Cliente,TiempoLLave,TiempoActualizacion");
		csv.print("Cliente"+id+",");
		String respuesta = "";
		escritor.println(HOLA);
		
		respuesta = lector.readLine();
		
		if (respuesta.equals(INICIO)) {
			String alg = ALGORITMOS;
			for (int i = 0; i < ALGS.length; i++) {
				alg += ":" + ALGS[i];
			}
			escritor.println(alg);
		} else {
			System.out.println("ERROR: Mensaje erróneo del servidor: " + respuesta);
			return;
		}
		
		java.security.cert.X509Certificate certClt;
		respuesta = lector.readLine();
		int tamanioBytes = 0;
		if (respuesta.equals(ESTADO + ":" + OK)) {
			escritor.println(CERTCLNT);
			certClt = certificado();
			byte[] myByte = certClt.getEncoded(); 
			tamanioBytes = myByte.length;
			socket.getOutputStream().write(myByte);
			socket.getOutputStream().flush();
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
				CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	            byte[] certificadoClienteBytes = new byte[5000]; // buffer para almacenar los bytes del certificado (en cliente, este tiene un un tamanio de mas o menos467 bytes)
	            
	            socket.getInputStream().read(certificadoClienteBytes);
	            InputStream inputStream = new ByteArrayInputStream(certificadoClienteBytes);
            	certificadoServidor = (X509Certificate)certFactory.generateCertificate(inputStream);
            	
            	escritor.println(ESTADO + ":" + OK);
			}
		} else if (respuesta.equals(ESTADO + ":" + ERROR)) {
			System.out.println("ERROR: El servidor envió ERROR como respuesta.");
			return;
		} else {
			System.out.println("ERROR: Mensaje erróneo del servidor: " + respuesta);
			return;
		}
		
		respuesta = "";
		//Inicia el proceso de la llave simétrica
		long startTime = System.currentTimeMillis();
		respuesta = lector.readLine();
		
		//8String[] resp = respuesta.split(":");
		System.out.println(respuesta);
		//8System.out.println(resp[0]);
		if (respuesta.equals(INICIO)) {
			//8String ll = resp[1];
			//System.out.println("01");
			//8Cipher decifrador = Cipher.getInstance(ALGS[1]);
			//System.out.println("02");
			//8decifrador.init(Cipher.DECRYPT_MODE, llavePrivada);
			//System.out.println("03");
			//8byte[] c = DatatypeConverter.parseHexBinary(ll);
			//System.out.println("04");
			//8byte[] descifrado = decifrador.doFinal(c);
			//System.out.println("1");
			//8SecretKey key = new SecretKeySpec(descifrado, 0, descifrado.length, ALGS[0]); //Obtenemos la llave secreta
			//Termina el proceso de la llave simétrica
			long elapsedTime = System.currentTimeMillis() - startTime;
			long elapsedSeconds = elapsedTime / 1000;
			long secondsDisplay = elapsedSeconds % 60;
			long elapsedMinutes = elapsedSeconds / 60;
			System.out.println(elapsedTime);
			csv.print(elapsedTime+",");
			//8decifrador=Cipher.getInstance(ALGS[0]);
			//System.out.println("8");
			//8decifrador.init(Cipher.ENCRYPT_MODE, key);
			//System.out.println("9");
			//8byte[] posEncriptado = decifrador.doFinal(posicion.getBytes()); //Encriptamos la posicion con la llave secreta
			//System.out.println("10");
			
			/*Mac mac = Mac.getInstance(ALGS[2]);
			mac.init(key);
			byte[] posHash = DatatypeConverter.parseHexBinary(posicion);
			byte[] elHash = mac.doFinal(posHash);*/
			
			//8MessageDigest md5 = MessageDigest.getInstance("MD5");
			//md5.update(posicion.getBytes());
			//8byte[] elHash = md5.digest(posicion.getBytes());
			
			//System.out.println("12");
			//byte[] elHash = md5.digest();
			//System.out.println("13");
			//8System.out.println(posEncriptado);
			//8decifrador=Cipher.getInstance(ALGS[1]);
			//System.out.println("8");
			//8decifrador.init(Cipher.ENCRYPT_MODE, certificadoServidor.getPublicKey());
			//System.out.println("9");
			//8byte[] posHashEncriptado = decifrador.doFinal(elHash);
			//System.out.println("10");
			//8System.out.println("Hash md5 del cliente: " + DatatypeConverter.printHexBinary(elHash));
			
			//8escritor.println(ACT1 + ":" + DatatypeConverter.printHexBinary(posEncriptado));
			escritor.println(ACT1);
			startTime = System.currentTimeMillis();
			//System.out.println("14");
			//System.out.println(DatatypeConverter.printHexBinary(posHashEncriptado));
			//8escritor.println(ACT2 + ":" + DatatypeConverter.printHexBinary(posHashEncriptado));
			escritor.println(ACT2);
			//System.out.println("15");
		}
		
		respuesta = lector.readLine();
		long elapsedTime = System.currentTimeMillis() - startTime;
		long elapsedSeconds = elapsedTime / 1000;
		long secondsDisplay = elapsedSeconds % 60;
		long elapsedMinutes = elapsedSeconds / 60;
		System.out.println(elapsedTime);
		csv.println(elapsedTime);
		csv.close();
		if (respuesta.equals(ESTADO + ":" + OK)) {
			System.out.println("OK: Mensaje encriptado y enviado correctamente.");
		} else if (respuesta.equals(ESTADO + ":" + ERROR)) {
			System.out.println("ERROR: El servidor respondió con error a los mensajes encriptados.");
			return;
		} else {
			System.out.println("ERROR: Mensaje erróneo del servidor: " + respuesta);
			return;
		}
		
	}

	private X509Certificate certificado() throws CertificateParsingException, CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
		String stringDate1 = "2016-10-01";
	    String stringDate2 = "2020-12-20";
	    DateFormat format = new SimpleDateFormat("yyyy-MM-dd");
	    Date startDate = null;
	    Date expiryDate = null;
	    try
	    {
	    	startDate = format.parse(stringDate1);
	    	expiryDate = format.parse(stringDate2);
	    }
	    catch (Exception e) {}
	    
		BigInteger serialNumber = new BigInteger(128, new Random());       // serial number for certificate
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = generator.genKeyPair();   
		this.llavePrivada = keyPair.getPrivate();
		
		 X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		    nameBuilder.addRDN(BCStyle.OU, "OU");
		    nameBuilder.addRDN(BCStyle.O, "O");
		    nameBuilder.addRDN(BCStyle.CN, "CN");
		    
		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(nameBuilder.build(), serialNumber, startDate, expiryDate, nameBuilder.build(), keyPair.getPublic());
	    X509Certificate certificate = null;
	    try
	    {
	      ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
	      certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
	    }
	    catch (Exception e)
	    {}
	    
	    return certificate;
	}
/**
	public static void main(String[] args) {
		try {
			Cliente c = new Cliente(1);
			c.ejecutar();
		} catch (Exception e) {e.printStackTrace();}
	}
*/
}
