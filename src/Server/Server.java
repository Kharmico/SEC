/**
 * 
 */
package Server;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Hashtable;

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

import com.sun.net.httpserver.HttpServer;

import Exceptions.UserAlreadyRegisteredException;
import RemoteTypes.IServer;

/**
 * @author paulo
 *
 */
@Path("/Server")
public class Server implements IServer {

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
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, AlreadyBoundException {
		if (args.length == 0) {
			manager = new Manager(DEFAULT_KS_PASSWORD.getPassword());
		} else {
			manager = args.length > 1 ? new Manager(args[1], args[0].toCharArray())
					: new Manager(args[0].toCharArray());
		}

		InetAddress s = localhostAddress();
//		String myUrl = String.format("http://%s:%s/", s.getCanonicalHostName(), PORT);
		String myUrl = String.format("http://%s:%s/", "localhost", PORT);
		System.out.println("my url: "+myUrl);
		
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
		JSONParser parser = new JSONParser();
		JSONObject json;
		try {
			json = (JSONObject) parser.parse(param);

			String pubKey = (String) json.get("pubKey");
			ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode((pubKey.getBytes())));
			ObjectInputStream is = new ObjectInputStream(in);
			Key k= ((Key) is.readObject());
			System.out.print("pubkey " + Base64.getEncoder().encodeToString(k.getEncoded()));
			manager.register(k);

			return Response.status(200).build();
		} catch (Exception e1) {
			e1.printStackTrace();
			return Response.status(400).build();
		}

	}

	@Override
	public void register(Key publicKey) throws RemoteException {
		// TODO Auto-generated method stub
		manager.register(publicKey);

	}

	@Override
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub
		manager.put(publicKey, domain, username, password);
	}

	@Override
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return manager.get(publicKey, domain, username);
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
