/**
 * 
 */
package Client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.net.ssl.HostnameVerifier;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.client.ClientConfig;
import org.json.simple.JSONObject;

/**
 * @author paulo
 *
 */
public class ClientI {

	private static WebTarget target;
	private static Client client;
	private static final String URL = "http://localhost:9000";

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		// TODO Auto-generated method stub

		ClientConfig config = new ClientConfig();
		Client client = ClientBuilder.newClient(config);
		target = client.target(UriBuilder.fromUri(URL).build());
		JSONObject j = new JSONObject();

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, random);
		KeyPair pair = keyGen.generateKeyPair();
		System.out.print("pubkey " + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(pair.getPublic());
		oos.close();
		String s = Base64.getEncoder().encodeToString(baos.toByteArray());
		System.out.print("pubkey " + s);
		j.put("pubKey", s);

		System.out.println("cliente tenta servidpor");
		target.path(String.format("/Server/Register")).request().accept(MediaType.APPLICATION_JSON)
				.post(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));
		// Response response = target.request().post( Entity.entity("PublicKey",
		// MediaType.APPLICATION_JSON));

	}

}
