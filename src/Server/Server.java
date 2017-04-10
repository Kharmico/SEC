/**
 * 
 */
package Server;

import java.math.BigInteger;
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
		int port = args.length > 0 ? Integer.parseInt(args[0]) : PORT;
		manager = args.length >1 ?new Manager(args[2], args[1].toCharArray()):new Manager(DEFAULT_KS_PASSWORD.getPassword());
		
		CryptoFunctions.setJcePolicy();
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

	@GET
	@Path("/Init/{json}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response init(@PathParam("json") String param) {

		System.out.println("INIT called");
		System.out.println(param);

		JSONObject json;
		try {
			json = getJason(param);
			Key serverPrivKey = manager.getServerPrivateKey();
			String encriptedFKey=((String) json.get("symmetricKey"));
			String serializedFKey=new String(CryptoFunctions.decrypt_data_asymmetric(encriptedFKey.getBytes(), serverPrivKey));
			Key fKey=(Key) CryptoFunctions.desSerialize(serializedFKey);
			//get nonce
			//byte[] hashed_nonce = CryptoFunctions.getHashMessage(((String) json.get("nonce")).getBytes());
			//byte[] signed_nonce = CryptoFunctions.getHashMessage(((String) json.get("signatureNonce")).getBytes());
			
			byte[] signature_fKey = CryptoFunctions
					.decrypt_data_symmetric(((String) json.get("symmetricKeySignature")).getBytes(), fKey);
			String pubKey = new String(CryptoFunctions.decrypt_data_symmetric(((String) json.get("pubKey")).getBytes(), fKey));
			byte[] signature_pubKey = CryptoFunctions
					.decrypt_data_symmetric(((String) json.get("pubKeySignature")).getBytes(), fKey);
			Key pkClient = (Key) CryptoFunctions.desSerialize(pubKey);
			if (!CryptoFunctions.verifySignature(pubKey.getBytes(), signature_pubKey, (PublicKey) pkClient)) {
				return Response.status(400).build();
			}
			if (!CryptoFunctions.verifySignature(serializedFKey.getBytes(), signature_fKey, (PublicKey) pkClient)) {
				return Response.status(400).build();
			}	
			
			String serialized_dfhClient=new String(CryptoFunctions.decrypt_data_symmetric(((String) json.get("dfhPubKey")).getBytes(), fKey));
			byte[] signature_dfhClient = CryptoFunctions.decrypt_data_symmetric(((String) json.get("dfhPubKeySignature")).getBytes(), fKey);
			Key dfhClient = (Key) CryptoFunctions.desSerialize(serialized_dfhClient);
			if (!CryptoFunctions.verifySignature(serialized_dfhClient.getBytes(), signature_dfhClient, (PublicKey) pkClient)) {
				return Response.status(400).build();
			}
			String serialized_g=new String(CryptoFunctions.decrypt_data_symmetric(((String) json.get("g")).getBytes(), fKey));
			byte[] signature_g =CryptoFunctions.decrypt_data_symmetric(((String) json.get("gSignature")).getBytes(), fKey);
			BigInteger g = (BigInteger) CryptoFunctions.desSerialize(serialized_g);
			if (!CryptoFunctions.verifySignature(serialized_g.getBytes(), signature_g, (PublicKey) pkClient)) {
				return Response.status(400).build();
			}		
			String serialized_p=new String(CryptoFunctions.decrypt_data_symmetric(((String) json.get("p")).getBytes(), fKey));
			byte[] signature_p =CryptoFunctions.decrypt_data_symmetric(((String) json.get("pSignature")).getBytes(), fKey);
			BigInteger p = (BigInteger) CryptoFunctions.desSerialize(serialized_p);
			if (!CryptoFunctions.verifySignature(serialized_p.getBytes(), signature_p, (PublicKey) pkClient)) {
				return Response.status(400).build();
			}
			
			String deviceId=new String(CryptoFunctions.decrypt_data_symmetric(((String) json.get("deviceID")).getBytes(), fKey));
			byte[] signature_deviceId =CryptoFunctions.decrypt_data_symmetric(((String) json.get("deviceIdSignature")).getBytes(), fKey);
			if (!CryptoFunctions.verifySignature(deviceId.getBytes(), signature_deviceId, (PublicKey) pkClient)) {
				return Response.status(400).build();
			}		
			Key pk = manager.init(pkClient, dfhClient, g, p,deviceId);

			System.out.println("Register ok");
			return Response.ok(Base64.getEncoder().encode(pk.getEncoded())).build();
		} catch (UserAlreadyRegisteredException u) {
			return Response.status(400).build();
		} catch (Exception e1) {
			e1.printStackTrace();
			return Response.status(400).build();
		}

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
			
			
			Key k = (Key) CryptoFunctions.desSerialize(pubKey);
			String deviceId=(String) json.get("deviceID");
			Key sessionKey = manager.getSessionKey((PublicKey) k,deviceId);
			byte[] signature_pubKey = CryptoFunctions.decrypt_data_symmetric(((String) json.get("pubKeySignature")).getBytes(),sessionKey);
			if (!CryptoFunctions.verifySignature(pubKey.getBytes(), signature_pubKey, (PublicKey) k)) {
				return Response.status(400).build();
			}
			byte[] hashed_nonce = ((String) json.get("nonce")).getBytes();
			byte[] signed_nonce = ((String) json.get("nonceSignature")).getBytes();
			if (!CryptoFunctions.verifySignature(hashed_nonce, signed_nonce, (PublicKey) k))
				return Response.status(400).build();
				//.digest automatically makes the checksums
			CryptoFunctions.getHashMessage(hashed_nonce);
			
			byte[] signature_deviceId =CryptoFunctions.decrypt_data_symmetric(((String) json.get("deviceIdSignature")).getBytes(), sessionKey);
			if (!CryptoFunctions.verifySignature(deviceId.getBytes(), signature_deviceId, (PublicKey) k)) {
				return Response.status(400).build();
			}
			manager.register(k);

			System.out.println("Register ok");
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
			String pubKey = (String) json.get("pubKey");
			
			Key k = (Key) CryptoFunctions.desSerialize(pubKey);
			String deviceId=(String) json.get("deviceID");
			Key sessionKey = manager.getSessionKey((PublicKey) k,deviceId);
			byte[] signature_pubKey = CryptoFunctions.decrypt_data_symmetric(((String) json.get("pubKeySignature")).getBytes(),sessionKey);
			if (!CryptoFunctions.verifySignature(pubKey.getBytes(), signature_pubKey, (PublicKey) k)) {
				Response.status(400).build();
			}
			
			byte[] signature_deviceId =CryptoFunctions.decrypt_data_symmetric(((String) json.get("deviceIdSignature")).getBytes(), sessionKey);
			if (!CryptoFunctions.verifySignature(deviceId.getBytes(), signature_deviceId, (PublicKey) k)) {
				return Response.status(400).build();
			}
			byte[] username = CryptoFunctions.decrypt_data_symmetric(((String) json.get("username")).getBytes(),
					sessionKey);
			byte[] signature_username = CryptoFunctions
					.decrypt_data_symmetric(((String) json.get("usernameSignature")).getBytes(), sessionKey);

			if (!CryptoFunctions.verifySignature(username, signature_username, (PublicKey) k))
				return Response.status(400).build();

			byte[] domain = CryptoFunctions.decrypt_data_symmetric(((String) json.get("domain")).getBytes(),
					sessionKey);

			byte[] signature_domain = CryptoFunctions
					.decrypt_data_symmetric(((String) json.get("domainSignature")).getBytes(), sessionKey);
			if (!CryptoFunctions.verifySignature(domain, signature_domain, (PublicKey) k))
				return Response.status(400).build();
			
			byte[] hashed_nonce = ((String) json.get("nonce")).getBytes();
			byte[] signed_nonce = ((String) json.get("nonceSignature")).getBytes();
			if (!CryptoFunctions.verifySignature(hashed_nonce, signed_nonce, (PublicKey) k))
				return Response.status(400).build();
				//.digest automatically makes the checksums
			CryptoFunctions.getHashMessage(hashed_nonce);

			byte[] password = CryptoFunctions.decrypt_data_symmetric(((String) json.get("password")).getBytes(),
					sessionKey);

			byte[] signature_password = CryptoFunctions
					.decrypt_data_symmetric(((String) json.get("passwordSignature")).getBytes(), sessionKey);
			if (!CryptoFunctions.verifySignature(password, signature_password, (PublicKey) k))
				return Response.status(400).build();
			
			manager.put(k, domain, username, password);
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

			String pubKey = (String) json.get("pubKey");
			
			Key k = (Key) CryptoFunctions.desSerialize(pubKey);
			String deviceId=(String) json.get("deviceID");
			Key sessionKey = manager.getSessionKey((PublicKey) k,deviceId);
			byte[] signature_pubKey = CryptoFunctions.decrypt_data_symmetric(((String) json.get("pubKeySignature")).getBytes(),sessionKey);
			
			if (!CryptoFunctions.verifySignature(pubKey.getBytes(), signature_pubKey, (PublicKey) k))
				return Response.status(400).build();
			
			
			byte[] signature_deviceId =CryptoFunctions.decrypt_data_symmetric(((String) json.get("deviceIdSignature")).getBytes(), sessionKey);
			
			if (!CryptoFunctions.verifySignature(deviceId.getBytes(), signature_deviceId, (PublicKey) k)) {
				return Response.status(400).build();
			}
			byte[] username = CryptoFunctions.decrypt_data_symmetric(((String) json.get("username")).getBytes(),
					sessionKey);
			byte[] signature_username = CryptoFunctions
					.decrypt_data_symmetric(((String) json.get("usernameSignature")).getBytes(), sessionKey);

			if (!CryptoFunctions.verifySignature(username, signature_username, (PublicKey) k))
				return Response.status(400).build();

			byte[] domain = CryptoFunctions.decrypt_data_symmetric(((String) json.get("domain")).getBytes(),
					sessionKey);
			byte[] signature_domain = CryptoFunctions
					.decrypt_data_symmetric(((String) json.get("domainSignature")).getBytes(), sessionKey);
			if (!CryptoFunctions.verifySignature(domain, signature_domain, (PublicKey) k))
				return Response.status(400).build();
			
			byte[] hashed_nonce = ((String) json.get("nonce")).getBytes();
			byte[] signed_nonce = ((String) json.get("nonceSignature")).getBytes();
			if (!CryptoFunctions.verifySignature(hashed_nonce, signed_nonce, (PublicKey) k))
				return Response.status(400).build();
				//.digest automatically makes the checksums
			CryptoFunctions.getHashMessage(hashed_nonce);
			
			byte[] password = manager.get(k, domain, username);
			byte[] pw = CryptoFunctions.encrypt_data_symmetric(password, sessionKey);

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
