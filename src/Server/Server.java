/**
 * 
 */
package Server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

/**
 * @author paulo
 *
 */
@Path("/Server")
public class Server {

	public static final String SERVER_NAME = "Server";
	private static final PasswordProtection DEFAULT_KS_PASSWORD = new PasswordProtection(
			"a26tUfrGg4e4LHX".toCharArray());
	private static final int PORT = 9000;

	private static Manager manager;

	public Server() {
	}

	/**
	 * @param args
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws AlreadyBoundException
	 */
	public static void main(String[] args)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		if (args.length == 0) {
			manager = new Manager(DEFAULT_KS_PASSWORD.getPassword());
		} else {
			manager = args.length > 1 ? new Manager(args[1], args[0].toCharArray())
					: new Manager(args[0].toCharArray());
		}

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
			Key k = (Key) desSerialize(pubKey);
			manager.register(k);

			return Response.status(200).build();
		} catch (Exception e1) {
			e1.printStackTrace();
			return Response.status(400).build();
		}

	}

	@PUT
	@Path("/Put")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response put(String param) {
		System.out.println("Put called");
		System.out.println("Json " + param);

		JSONObject json;
		try {
			json = getJason(param);
			String username = (String) json.get("username");
			String domain = (String) json.get("domain");
			System.out.println("domain no PUT "+domain);
			
			String password = (String) json.get("password");
			System.out.println("password no PUT "+password);
			String pubKey = (String) json.get("pubKey");
			Key publicKey = ((Key) desSerialize(pubKey));
			manager.put(publicKey, domain.getBytes(),username.getBytes(), password.getBytes());

			System.out.println("pubkey " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
			return Response.status(200).build();
		} catch (Exception e1) {
			e1.printStackTrace();
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
			json = getJason(param);
		
			String username = (String) json.get("username");
			String domain = (String) json.get("domain");
			System.out.println("username "+ username);
			System.out.println("domain no GET "+domain);
			String pubKey = (String) json.get("pubKey");
			Key publicKey = ((Key) desSerialize(pubKey));
			
			System.out.println("pubkey " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
			byte[] password = manager.get(publicKey, domain.getBytes(), username.getBytes());
		String pw = new String(password);
		
			
			return Response.ok(pw).build();
		} catch (Exception e1) {
			e1.printStackTrace();
			return Response.status(400).build();
		}

	}

	private JSONObject getJason(String param) throws ParseException {
		JSONParser parser = new JSONParser();
		return (JSONObject) parser.parse(param);
	}

	private Object desSerialize(String obj) throws ClassNotFoundException, IOException {
		ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode((obj.getBytes())));
		ObjectInputStream is = new ObjectInputStream(in);
		return is.readObject();
	}

	private byte[] decodeString(String string) {
		return Base64.getDecoder().decode(string);
	}

	private String encodeString(byte[] array) {
		return Base64.getEncoder().encodeToString(array);
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
}
