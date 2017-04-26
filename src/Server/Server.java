/**
 * 
 */
package Server;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore.PasswordProtection;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.sun.net.httpserver.HttpServer;

import Crypto.CryptoFunctions;
import Crypto.KeyStoreFunc;
import Crypto.Message;
import Crypto.Password;
import Exceptions.InvalidSignatureException;
import Exceptions.UserAlreadyRegisteredException;

/**
 * @author paulo
 *
 */
@Path("/Server")
public class Server {

	public static final String SERVER_NAME = "Server";
	public static final int PORT = 9000;
	public static final int OK = 200;
	public static final int BAD_REQUEST = 400;
	// this password should be passed as parameter when server boots
	private static PasswordProtection DEFAULT_KS_PASSWORD = new PasswordProtection("a26tUfrGg4e4LHX".toCharArray());
	private static Manager manager;

	public Server() {
	}

	/**
	 * @param args
	 * @throws Exception
	 * @throws AlreadyBoundException
	 */
	public static void main(String[] args) throws Exception {
		int port = args.length > 0 ? Integer.parseInt(args[0]) : PORT;
		manager = args.length > 1 ? new Manager(args[2], args[1].toCharArray(), port)
				: new Manager(DEFAULT_KS_PASSWORD.getPassword(), port);

//		CryptoFunctions.setJcePolicy();
		// InetAddress s = localhostAddress();
		// String myUrl = String.format("http://%s:%s/",
		// s.getCanonicalHostName(), PORT);
		String myUrl = String.format("http://%s:%s/", "localhost", port);
		System.out.println("my url: " + myUrl);
		URI baseUri = UriBuilder.fromUri(myUrl).build();
		ResourceConfig config = new ResourceConfig();
		config.register(Server.class);
		HttpServer server = JdkHttpServerFactory.createHttpServer(baseUri, config);
		System.out.println("Server is running");
	}

	@POST
	@Path("/Register")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response register(String param) {
		System.out.println("Register called");
		System.out.println(param);

		JSONObject json;
		try {
			json = getJason(param);
			Message m = this.checkSignature(json);
			manager.register(m.getPubKey());
			return Response.status(200).build();
		} catch (UserAlreadyRegisteredException u) {
			u.printStackTrace();
			return Response.status(400).build();
		} catch (Exception e1) {
			e1.printStackTrace();
			return Response.status(400).build();
		}

	}

	@POST
	@Path("/Put")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response put(String param) {
		System.out.println("Put called");
		System.out.println("Json " + param);

		JSONObject json;
		try {
			json = getJason(param);
			Message m = this.checkSignature(json);
			manager.put(m.getPubKey(), m.getDomain(), m.getUsername(), m.getPassword());
			return Response.status(200).build();
		} catch (Exception e1) {
			e1.printStackTrace();
			return Response.status(400).build();
		}

	}

	@SuppressWarnings("unchecked")
	@GET
	@Path("/Get/{json}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response get(@PathParam("json") String param) {

		System.out.println("Get called");
		System.out.println("Json " + param);

		JSONObject json;
		try {
			json = getJason(param);
			json = getJason(param);
			Message m = this.checkSignature(json);
			Password password = manager.get(m.getPubKey(), m.getDomain(), m.getUsername());
			m.setPassword(password);
			String serialized_m = CryptoFunctions.serialize(m);
			json= new JSONObject();
			byte[] signedMessage = CryptoFunctions.sign_data(serialized_m.getBytes(), manager.getServerPrivateKey());
			json.put("message", serialized_m);
			json.put("signature",new String( signedMessage));
			

			
			
			return Response.ok(json).build();
		} catch (Exception e1) {
			e1.printStackTrace();
			return Response.status(400).build();
		}

	}

	private JSONObject getJason(String param) throws ParseException {
		JSONParser parser = new JSONParser();
		return (JSONObject) parser.parse(param);
	}

	private static InetAddress localhostAddress() {
		try {
			try {
				Enumeration<NetworkInterface> e = NetworkInterface.getNetworkInterfaces();
				while (e.hasMoreElements()) {
					NetworkInterface n = e.nextElement();
					Enumeration<InetAddress> ee = n.getInetAddresses();
					while (ee.hasMoreElements()) {
						InetAddress i = ee.nextElement();
						if (i instanceof Inet4Address && !i.isLoopbackAddress())
							return i;
					}
				}
			} catch (SocketException e) {
				// do nothing
			}
			return InetAddress.getLocalHost();
		} catch (UnknownHostException e) {
			return null;
		}
	}

	public static void stop() {
		System.exit(1);
	}

	private Message checkSignature(JSONObject json) throws InvalidSignatureException, ClassNotFoundException,
			IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		String serialized_message = (String) json.get("message");

		Message m = (Message) CryptoFunctions.desSerialize(serialized_message);
		byte[] signature = ((String) json.get("messageSignature")).getBytes();
		PublicKey publicKey = m.getPubKey();
		// check signature
		if (!CryptoFunctions.verifySignature(serialized_message.getBytes(), signature, publicKey)) {
			throw new InvalidSignatureException();
		}
		// .digest automatically makes the checksums
		// checkFreesheness
		CryptoFunctions.getHashMessage(m.getNounce());
		return m;
	}

}
