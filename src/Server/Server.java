/**
 * 
 */
package Server;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyStore.PasswordProtection;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.SecretKey;
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
	private static SecretKey MASTER_KEY;
	private static final PasswordProtection DEFAULT_KS_PASSWORD = new PasswordProtection(
			"a26tUfrGg4e4LHX".toCharArray());

	private static Manager manager;

	public Server() {
	}

	/**
	 * @param args
	 * @throws Exception
	 * @throws AlreadyBoundException
	 */
	public static void main(String[] args) throws Exception {
		if (args.length == 0) {
			manager = new Manager(DEFAULT_KS_PASSWORD.getPassword());
		} else {
			manager = args.length > 1 ? new Manager(args[1], args[0].toCharArray())
					: new Manager(args[0].toCharArray());
		}
		MASTER_KEY = (SecretKey) CryptoFunctions.desSerialize(
				"rO0ABXNyAB9qYXZheC5jcnlwdG8uc3BlYy5TZWNyZXRLZXlTcGVjW0cLZuIwYU0CAAJMAAlhbGdvcml0aG10ABJMamF2YS9sYW5nL1N0cmluZztbAANrZXl0AAJbQnhwdAADQUVTdXIAAltCrPMX+AYIVOACAAB4cAAAABCJzON5PSWnsYxFrxWAd1dA");

		// InetAddress s = localhostAddress();
		// String myUrl = String.format("http://%s:%s/",
		// s.getCanonicalHostName(), PORT);
		String myUrl = String.format("http://%s:%s/", "localhost", PORT);
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

			String pubKey = (String) json.get("pubKey");
			String signature_pubKey = (String) json.get("pubKeySignature");
			Key k = (Key) CryptoFunctions.desSerialize(pubKey);
			if (!CryptoFunctions.verifySignature(pubKey.getBytes(), signature_pubKey.getBytes(), (PublicKey) k)) {
				return Response.status(400).build();
			}
			manager.register(k);

			System.out.println("Register ok");
			return Response.status(200).build();
		} catch (UserAlreadyRegisteredException u) {
			return Response.status(400).build();
		} catch (Exception e1) {

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
			// Key superKey = new SecretKeySpec(MASTER_KEY, "AES");

			String pubKey = (String) json.get("pubKey");
			String signature_pubKey = (String) json.get("pubKeySignature");
			Key k = (Key) CryptoFunctions.desSerialize(pubKey);
			if (!CryptoFunctions.verifySignature(pubKey.getBytes(), signature_pubKey.getBytes(), (PublicKey) k)) {
				Response.status(400).build();
			}

			byte[] username = CryptoFunctions.decrypt_data_symmetric((String) json.get("username"), MASTER_KEY);
			byte[] signature_username = CryptoFunctions.decrypt_data_symmetric((String) json.get("usernameSignature"),
					MASTER_KEY);

			if (!CryptoFunctions.verifySignature(username, signature_username, (PublicKey) k))
				return Response.status(400).build();

			byte[] domain = CryptoFunctions.decrypt_data_symmetric((String) json.get("domain"), MASTER_KEY);
			byte[] signature_domain = CryptoFunctions.decrypt_data_symmetric((String) json.get("domainSignature"),
					MASTER_KEY);
			if (!CryptoFunctions.verifySignature(domain, signature_domain, (PublicKey) k))
				return Response.status(400).build();

			byte[] password = CryptoFunctions.decrypt_data_symmetric((String) json.get("password"), MASTER_KEY);
			byte[] signature_password = CryptoFunctions.decrypt_data_symmetric((String) json.get("passwordSignature"),
					MASTER_KEY);
			if (!CryptoFunctions.verifySignature(password, signature_password, (PublicKey) k))
				return Response.status(400).build();

			manager.put(k, domain, username, password);

			// System.out.println("pubkey " +
			// Base64.getEncoder().encodeToString(k.getEncoded()));
			return Response.status(200).build();
		} catch (Exception e1) {

			return Response.status(400).build();
		}

	}

	@GET
	@Path("/Get/{json}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response get(@PathParam("json") String param) {

		System.out.println("Get called");
		System.out.println("Json " + param);

		JSONObject json;
		try {
//			param=URLDecoder.decode(param, "UTF-8");
			// Key superKey = new SecretKeySpec(MASTER_KEY, "AES");
			json = getJason(param);

			String pubKey = (String) json.get("pubKey");
			String signature_pubKey = (String) json.get("pubKeySignature");
			Key k = (Key) CryptoFunctions.desSerialize(pubKey);
			if (!CryptoFunctions.verifySignature(pubKey.getBytes(), signature_pubKey.getBytes(), (PublicKey) k))
				return Response.status(400).build();
			String aux = (String) json.get("username");
			byte[] username = CryptoFunctions.decrypt_data_symmetric((String) json.get("username"), MASTER_KEY);
			byte[] signature_username = CryptoFunctions.decrypt_data_symmetric((String) json.get("usernameSignature"),
					MASTER_KEY);

			if (!CryptoFunctions.verifySignature(username, signature_username, (PublicKey) k))
				return Response.status(400).build();

			byte[] domain = CryptoFunctions.decrypt_data_symmetric((String) json.get("domain"), MASTER_KEY);
			byte[] signature_domain = CryptoFunctions.decrypt_data_symmetric((String) json.get("domainSignature"),
					MASTER_KEY);
			if (!CryptoFunctions.verifySignature(domain, signature_domain, (PublicKey) k))
				return Response.status(400).build();

			byte[] password = manager.get(k, domain, username);

			String pw = CryptoFunctions.encrypt_data_symmetric(new String(password), MASTER_KEY);

			return Response.ok(pw).build();
		} catch (Exception e1) {

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

}
