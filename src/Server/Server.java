/**
 * 
 */
package Server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

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

import Client.ClientConnections;
import Crypto.CryptoFunctions;
import Crypto.KeyStoreFunc;
import Crypto.Message;
import Crypto.Password;
import Crypto.IServer;
import Crypto.ServerClass;
import Exceptions.InvalidSignatureException;
import Exceptions.NullByzantineQuorumException;
import Exceptions.UserAlreadyRegisteredException;

/**
 * @author paulo
 *
 */
@Path("/Server")
public class Server {
	private static final String CERT_PATH = System.getProperty("user.dir") + "\\Resources\\serversec%s.cer";
	public static final String SERVER_NAME = "Server";
	public static final int PORT = 9000;
	public static final int OK = 200;
	public static final int BAD_REQUEST = 400;
	// this password should be passed as parameter when server boots
	private static PasswordProtection DEFAULT_KS_PASSWORD = new PasswordProtection("a26tUfrGg4e4LHX".toCharArray());
	private static Manager manager;
	private static ConcurrentMap<ByteArrayWrapper, ByteArrayWrapper> nounces;
	private static ConcurrentMap<String, IServer> servers;
	private static volatile int rid = 0;
	private static volatile int wts = 0;
	private static final int F = 1;
	private static String myUrl;
	public Server() {
	}

	/**
	 * @param args
	 * @throws Exception
	 * @throws AlreadyBoundException
	 */
	public static void main(String[] args) throws Exception {
		int port = args.length > 0 ? Integer.parseInt(args[0]) : PORT;
		// manager = args.length > 1 ? new Manager(args[2],
		// args[1].toCharArray(), port)
		// : new Manager(DEFAULT_KS_PASSWORD.getPassword(), port);
		manager = new Manager(DEFAULT_KS_PASSWORD.getPassword(), port);
		servers = new ConcurrentHashMap<String, IServer>();

		for (int i = 1; i < args.length; i++) {
			IServer s = new ServerClass(args[i]);
			URI u = new URI(s.getUrl());
			u.getPort();
			System.out.println("URI AND PORT: " + u + " " + u.getPort());
			PublicKey serverPubKey = KeyStoreFunc.getPublicKeyCertificate(String.format(CERT_PATH, u.getPort()));
			s.setPubKey(serverPubKey);
			servers.put(args[i], s);
		}
		// CryptoFunctions.setJcePolicy();
		// InetAddress s = localhostAddress();
		// String myUrl = String.format("http://%s:%s/",
		// s.getCanonicalHostName(), PORT);
		myUrl = String.format("http://%s:%s/", "localhost", port);
		System.out.println("my url: " + myUrl);
		URI baseUri = UriBuilder.fromUri(myUrl).build();
		ResourceConfig config = new ResourceConfig();
		config.register(Server.class);
		HttpServer server = JdkHttpServerFactory.createHttpServer(baseUri, config);
		nounces = new ConcurrentHashMap<ByteArrayWrapper, ByteArrayWrapper>();
		manager.readUsersFile();
		System.out.println("Server is running");
		new Thread(() -> {
			try {
				for (;;) {
					manager.writeUsersFiles();
					Thread.sleep(59 * 1000);
				}
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		}).start();
	}

	@SuppressWarnings("unchecked")
	@GET
	@Path("/Register/{json}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response register(@PathParam("json") String param) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, UnrecoverableEntryException, KeyStoreException {
		System.out.println("Register called");
		System.out.println(param);

		JSONObject json = null;
		Message m = new Message();
		String serialized_m = null;
		byte[] signedMessage = null;
		int status = 0;
		try {
			json = getJason(param);
			m = this.checkSignatureClient(json);
			manager.register(m.getClientPubKey());

			status = OK;

		} catch (UserAlreadyRegisteredException u) {
			u.printStackTrace();
			status = BAD_REQUEST;

		} catch (Exception e1) {
			status = BAD_REQUEST;
		}
		byte[] nonce = CryptoFunctions.generateNonce();
		m.setNounce(nonce);
		json = new JSONObject();
		serialized_m = CryptoFunctions.serialize(m);
		signedMessage = CryptoFunctions.sign_data(serialized_m.getBytes(), manager.getServerPrivateKey());
		json.put("message", serialized_m);
		json.put("signature", new String(signedMessage));
		json.put("status", status);
		return Response.ok(json).build();
	}

	@SuppressWarnings("unchecked")
	@GET
	@Path("/Put/Server/{json}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response putServer(@PathParam("json") String param) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, UnrecoverableEntryException, KeyStoreException {
		System.out.println("Put/Server called");
		System.out.println("Json " + param);

		JSONObject json = null;
		Message m = new Message();
		String serialized_m = null;
		byte[] signedMessage = null;
		int status = 0;
		try {
			json = getJason(param);
			m = this.checkSignatureServer(json);
			manager.put(m.getClientPubKey(), m.getDomain(), m.getUsername(), m.getPassword());
			status = OK;
		} catch (UserAlreadyRegisteredException u) {
			u.printStackTrace();
			status = BAD_REQUEST;
		} catch (Exception e1) {
			status = BAD_REQUEST;
			e1.printStackTrace();
		}
		json = new JSONObject();
		byte[] nonce = CryptoFunctions.generateNonce();
		m.setNounce(nonce);
		serialized_m = CryptoFunctions.serialize(m);
		signedMessage = CryptoFunctions.sign_data(serialized_m.getBytes(), manager.getServerPrivateKey());
		json.put("message", serialized_m);
		json.put("signature", new String(signedMessage));
		json.put("status", status);
		return Response.ok(json).build();

	}

	@SuppressWarnings("unchecked")
	@GET
	@Path("/Get/Server/{json}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getServer(@PathParam("json") String param) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, UnrecoverableEntryException, KeyStoreException {

		System.out.println("Get/Server called");
		System.out.println("Json " + param);

		JSONObject json = null;
		Message m = new Message();
		String serialized_m = null;
		byte[] signedMessage = null;
		int status = 0;
		try {
			json = getJason(param);

			m = this.checkSignatureServer(json);
			Password password = manager.get(m.getClientPubKey(), m.getDomain(), m.getUsername());
			m.setPassword(password);

			status = OK;
		} catch (UserAlreadyRegisteredException u) {
			u.printStackTrace();
			status = BAD_REQUEST;
		} catch (Exception e1) {
			e1.printStackTrace();
			status = BAD_REQUEST;
		}
		byte[] nonce = CryptoFunctions.generateNonce();
		m.setNounce(nonce);
		serialized_m = CryptoFunctions.serialize(m);
		json = new JSONObject();

		signedMessage = CryptoFunctions.sign_data(serialized_m.getBytes(), manager.getServerPrivateKey());
		json.put("message", serialized_m);
		json.put("signature", new String(signedMessage));
		json.put("status", status);
		return Response.ok(json).build();
	}

	@SuppressWarnings("unchecked")
	@GET
	@Path("/Put/{json}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response put(@PathParam("json") String param) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, UnrecoverableEntryException, KeyStoreException {
		System.out.println("Put called");
		System.out.println("Json " + param);

		JSONObject json = null;
		Message m = new Message();
		String serialized_m = null;
		byte[] signedMessage = null;
		int status = 0;
		try {
			json = getJason(param);
//			Map<String, String> map = this.checkSignatureMap(json);
//			m = (Message) CryptoFunctions.desSerialize(map.get("message"));
			m=this.checkSignatureClient(json);
			// ---------------------------------------------------------
			// TODO: chame o write no server que faz triger do alg
			Password p = readOthers(m);
			Password np = m.getPassword();
			if (p != null)
				np.setTimeStamp(p.getTimeStamp() + 1);
			else {
				np.setTimeStamp(1);
			}
			m.setPassword(np);
			writeOthers(m);

			// ---------------------------------------------------------
			// ---------------------------------------------------------

			// manager.put(m.getClientPubKey(), m.getDomain(), m.getUsername(),
			// m.getPassword());
			status = OK;
		} catch (UserAlreadyRegisteredException u) {
			u.printStackTrace();
			status = BAD_REQUEST;
		} catch (Exception e1) {
			status = BAD_REQUEST;
			e1.printStackTrace();
		}
		json = new JSONObject();
		byte[] nonce = CryptoFunctions.generateNonce();
		m.setNounce(nonce);
		serialized_m = CryptoFunctions.serialize(m);
		signedMessage = CryptoFunctions.sign_data(serialized_m.getBytes(), manager.getServerPrivateKey());
		json.put("message", serialized_m);
		json.put("signature", new String(signedMessage));
		json.put("status", status);
		return Response.ok(json).build();

	}

	@SuppressWarnings("unchecked")
	@GET
	@Path("/Get/{json}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response get(@PathParam("json") String param) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, UnrecoverableEntryException, KeyStoreException {

		System.out.println("Get called");
		System.out.println("Json " + param);

		JSONObject json = null;
		Message m = new Message();
		String serialized_m = null;
		byte[] signedMessage = null;
		int status = 0;
		try {
			json = getJason(param);

//			Map<String, String> map = this.checkSignatureMap(json);
			m=this.checkSignatureClient(json);
					
			// ---------------------------------------------------------
			// TODO: chame o read no server que faz triger do alg
			Password p = readOthers(m);

			if (p != null) {
				m.setPassword(p);
				writeOthers(m);
			}
			// ---------------------------------------------------------
			Password password = manager.get(m.getClientPubKey(), m.getDomain(), m.getUsername());
			m.setPassword(password);

			status = OK;
		} catch (UserAlreadyRegisteredException u) {
			u.printStackTrace();
			status = BAD_REQUEST;
		} catch (Exception e1) {
			e1.printStackTrace();
			status = BAD_REQUEST;
		}
		byte[] nonce = CryptoFunctions.generateNonce();
		m.setNounce(nonce);
		serialized_m = CryptoFunctions.serialize(m);
		json = new JSONObject();

		signedMessage = CryptoFunctions.sign_data(serialized_m.getBytes(), manager.getServerPrivateKey());
		json.put("message", serialized_m);
		json.put("signature", new String(signedMessage));
		json.put("status", status);
		return Response.ok(json).build();
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

	private Message checkSignatureClient(JSONObject json) throws InvalidSignatureException, ClassNotFoundException,
			IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		String serialized_message = (String) json.get("message");

		Message m = (Message) CryptoFunctions.desSerialize(serialized_message);
		byte[] signature = ((String) json.get("messageSignature")).getBytes();
		PublicKey publicKey =m.getClientPubKey();
		// check signature
		if (!CryptoFunctions.verifySignature(serialized_message.getBytes(), signature, publicKey)) {
			throw new InvalidSignatureException();
		}
		CryptoFunctions.getHashMessage(m.getNounce());
		if (nounces.containsKey((new ByteArrayWrapper(m.getNounce())))) {
			throw new NullPointerException("no freshness");
		} else {
			nounces.put((new ByteArrayWrapper(m.getNounce())), (new ByteArrayWrapper(m.getNounce())));
		}
		return m;
	}

	private Message checkSignatureServer(JSONObject json) throws InvalidSignatureException,
			ClassNotFoundException, IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		Map<String, String> map = new HashMap<String, String>();
		String serialized_message = (String) json.get("message");
		Message m = (Message) CryptoFunctions.desSerialize(serialized_message);
		byte[] signature = ((String) json.get("messageSignature")).getBytes();
		String url =m.getUrl();
		IServer s =servers.get(url);
		if(s==null){
			throw new InvalidSignatureException();
		}
		PublicKey publicKey = s.getPubKey();
		// check signature
		if (!CryptoFunctions.verifySignature(serialized_message.getBytes(), signature, publicKey)) {
			throw new InvalidSignatureException();
		}
		CryptoFunctions.getHashMessage(m.getNounce());
		if (nounces.containsKey((new ByteArrayWrapper(m.getNounce())))) {
			throw new NullPointerException("no freshness");
		} else {
			nounces.put((new ByteArrayWrapper(m.getNounce())), (new ByteArrayWrapper(m.getNounce())));
		}
		return m;
	}

	private static Password readOthers(Message m) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnrecoverableEntryException, KeyStoreException {
		byte[] nonce = CryptoFunctions.generateNonce();
		m.setNounce(nonce);
		m.setUrl(myUrl);
		String serialized_message = CryptoFunctions.serialize(m);
		byte[] signed_message = CryptoFunctions.sign_data(serialized_message.getBytes(), manager.getServerPrivateKey());
		List<Password> readList = new LinkedList<Password>();
		m = new Message();
		Password pwAux = null;
		for (IServer s : servers.values()) {
			m = connect(s, serialized_message, signed_message, "Get/Server");
			if (validMessage(m)) {
				Password aux = m.getPassword();
				if (rid == m.getTimeStamp()) {
					readList.add(aux);
				}
			}
		}

		int countReplys = 0;
		for (Password pass : readList) {
			if (pass != null)
				countReplys++;
			else
				System.out.println("PASSWORD PASSWORD IS NULL");
		}

		System.out.println("PASSWORDAUX VALUE (counter): " + countReplys);

		if (countReplys > ((servers.size() + F) / 2)) {
			long tsAux = 0;
			for (Password passwordAux2 : readList) {
				if (passwordAux2 != null) {
					if (tsAux < passwordAux2.getTimeStamp()) {
						tsAux = passwordAux2.getTimeStamp();
						pwAux = passwordAux2;
					}
				}
			}
		}
		return pwAux;
	}

	private static void writeOthers(Message m) throws IOException, InvalidKeyException, NoSuchAlgorithmException,
			SignatureException, UnrecoverableEntryException, KeyStoreException {
		byte[] nonce = CryptoFunctions.generateNonce();
		m.setNounce(nonce);
		String serialized_message = CryptoFunctions.serialize(m);
		byte[] signed_message = CryptoFunctions.sign_data(serialized_message.getBytes(), manager.getServerPrivateKey());
		List<String> ackList = new LinkedList<String>();
		assert (ackList.size() == servers.size());
		for (IServer s : servers.values()) {
			Message r = connect(s, serialized_message, signed_message, "Put/Server");
			if (r.getStatus() == 200 && r.getTimeStamp() == wts)
				ackList.add("ack");
			System.out.println("GETTING STATUS STATUS: " + r.getStatus());
		}

		if (ackList.size() > ((servers.size() + F) / 2))
			ackList.clear();
		else {
			ackList.clear();
			throw new NullByzantineQuorumException("Not enough correct servers!");
		}
	}

	private static Message connect(IServer s, String message, byte[] signature_message, String webResource) {
		Message m = new Message();
		m.setStatus(400);
		try {
			JSONObject j = createJson(message, signature_message);

			String json = URLEncoder.encode(j.toJSONString(), "UTF-8");
			j = s.getTarget().path(String.format("/Server/%s/%s/", webResource, json)).request()
					.accept(MediaType.APPLICATION_JSON).get(JSONObject.class);
			String serialized_message = (String) j.get("message");
			byte[] signature = ((String) j.get("signature")).getBytes();

			if (CryptoFunctions.verifySignature(serialized_message.getBytes(), signature, s.getPubKey())) {
				m = ((Message) CryptoFunctions.desSerialize(serialized_message));
				CryptoFunctions.getHashMessage(m.getNounce());
				m.setStatus((int) j.get("status"));
				return m;
			}
		} catch (ConnectException e) {

		} catch (UnsupportedEncodingException e) {

		} catch (InvalidKeyException e) {

		} catch (SignatureException e) {

		} catch (NoSuchAlgorithmException e) {

		} catch (ClassNotFoundException e) {

		} catch (IOException e) {

		} catch (javax.ws.rs.ProcessingException e) {

		} catch (Exception e) {
			System.out.println("excepção------------------------------");
			// e.printStackTrace();
		}
		return m;
	}

	@SuppressWarnings("unchecked")
	private static JSONObject createJson(String message, byte[] signature_message) {
		JSONObject j = new JSONObject();
		j.put("message", message);
		j.put("messageSignature", new String(signature_message));
		return j;
	}

	private static boolean validMessage(Message m) {
		return m != null && m.getPassword() != null && m.getNounce() != null;
	}
}
