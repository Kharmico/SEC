/**
 * 
 */
package Client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.client.ClientConfig;
import org.json.simple.JSONObject;

import Crypto.CryptoFunctions;
import Exceptions.ConectionFailedException;

/**
 * @author paulo
 *
 */
public final class ClientConnections {

	public static final String SERVER_URL = "http://localhost:9000";
	public static final int OK = 200;
	public static final int BAD_REQUEST = 400;
	//para teste usamos um vvalor random para identificar o dispositivo na pratica deveria ser um ip adress
	

	private WebTarget target;
	private Client client;

	public ClientConnections() {
		
		ClientConfig config = new ClientConfig();
		client = ClientBuilder.newClient(config);
		target = client.target(UriBuilder.fromUri(SERVER_URL).build());

	}

	@SuppressWarnings("unchecked")
	public byte[] init(String pubKey, byte[] signature_pubKey, String dfhPubKey, byte[] signature_dfhPubKey, String g,
			byte[] signed_g, String p, byte[] signed_p, String symmetricKey, byte[] signed_symmetricKey,String deviceId,byte[] signed_deviceID)
			throws ConectionFailedException, ClassNotFoundException, IOException {
		JSONObject j = new JSONObject();
		j.put("pubKey", pubKey);
		j.put("pubKeySignature", new String(signature_pubKey));
		j.put("dfhPubKey", dfhPubKey);
		j.put("dfhPubKeySignature", new String(signature_dfhPubKey));
		j.put("g", g);
		j.put("gSignature", new String(signed_g));
		j.put("p", p);
		j.put("pSignature", new String(signed_p));
		j.put("symmetricKey", symmetricKey);
		j.put("symmetricKeySignature", new String(signed_symmetricKey));
		j.put("deviceID", deviceId);
		j.put("deviceIdSignature", new String(signed_deviceID));
		//nonce
		//j.put("nonce", new String(nonce));
		//j.put("nonceSignature", new String(signature_nonce));
		
		String json = URLEncoder.encode(j.toJSONString(), "UTF-8");

		WebTarget target = this.target.path(String.format("/Server/Init/%s/", json));
		return target.request().accept(MediaType.APPLICATION_JSON).get(byte[].class);

	}

	@SuppressWarnings("unchecked")
	public void register(String pubKey, byte[] signature_pubKey, byte[] nonce, byte[] signature_nonce,String deviceId,byte[] signed_deviceID) throws ConectionFailedException {
		JSONObject j = new JSONObject();
		j.put("pubKey", pubKey);
		j.put("pubKeySignature", new String(signature_pubKey));
		//nonce
		j.put("nonce", new String(nonce));
		j.put("nonceSignature", new String(signature_nonce));
		//deviceID
		j.put("deviceID", deviceId);
		j.put("deviceIdSignature", new String (signed_deviceID));
		
		WebTarget target = this.target.path(String.format("/Server/Register"));
		Response response = target.request().accept(MediaType.APPLICATION_JSON)
				.post(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));

		checkStatus(response);
	}

	@SuppressWarnings("unchecked")
	public void put(String pubKey, byte[] signature_pubKey, byte[] domain, byte[] signature_domain, byte[] username,
			byte[] signature_username, byte[] password, byte[] signature_password, byte[] nonce, byte[] signature_nonce,String deviceId,byte[] signed_deviceID) {
		JSONObject j = new JSONObject();
		j.put("pubKey", pubKey);
		j.put("pubKeySignature", new String(signature_pubKey));
		j.put("domain", new String(domain));
		j.put("domainSignature", new String(signature_domain));
		j.put("username", new String(username));
		j.put("usernameSignature", new String(signature_username));
		j.put("password", new String(password));
		j.put("passwordSignature", new String(signature_password));
		//nonce
		j.put("nonce", new String(nonce));
		j.put("nonceSignature", new String(signature_nonce));
		//deviceID
		j.put("deviceID", deviceId);
		j.put("deviceIdSignature",new String( signed_deviceID));
		
		WebTarget target = this.target.path(String.format("/Server/Put"));
		Response response = target.request().accept(MediaType.APPLICATION_JSON)
				.post(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));
		checkStatus(response);
	}

	@SuppressWarnings("unchecked")
	public byte[] get(String pubKey, byte[] signature_pubKey, byte[] domain, byte[] signature_domain, byte[] username,
			byte[] signature_username, byte[] nonce, byte[] signature_nonce,String deviceId,byte[] signed_deviceID) throws UnsupportedEncodingException {
		System.out.println("domain no client " + domain);
		JSONObject j = new JSONObject();
		j.put("pubKey", pubKey);
		j.put("pubKeySignature", new String(signature_pubKey));
		j.put("domain", new String(domain));
		j.put("domainSignature", new String(signature_domain));
		j.put("username", new String(username));
		j.put("usernameSignature", new String(signature_username));
		//nonce
		j.put("nonce", new String(nonce));
		j.put("nonceSignature", new String(signature_nonce));
		//deviceID
		j.put("deviceID", deviceId);
		j.put("deviceIdSignature",new String( signed_deviceID));
		
		String json = URLEncoder.encode(j.toJSONString(), "UTF-8");
		WebTarget target = this.target.path(String.format("/Server/Get/%s/", json));
		byte[] response = target.request().accept(MediaType.APPLICATION_JSON).get(byte[].class);
		return response;
	}

	private void checkStatus(Response res) {
		if (res.getStatus() == BAD_REQUEST)
			throw new BadRequestException();
		if (res.getStatus() != OK)
			throw new ConectionFailedException();
	}

}
