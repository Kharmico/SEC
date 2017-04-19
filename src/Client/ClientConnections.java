/**
 * 
 */
package Client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
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
import Crypto.Message;
import Exceptions.ConectionFailedException;

/**
 * @author paulo
 *
 */
public class ClientConnections {

	// public static final String SERVER_URL = "http://localhost:9000";
	public static final int OK = 200;
	public static final int BAD_REQUEST = 400;

	private Map<String, Server> servers;

	// para teste usamos um vvalor random para identificar o dispositivo na
	// pratica deveria ser um ip adress
	public ClientConnections(String[] urls) {
		this.servers = new HashMap<String, Server>();
		for (int i = 0; i < urls.length; i++) {
			this.servers.put(urls[i], new ServerClass(urls[i]));
		}

	}

	public void register(String message, byte[] signature_message) throws ConectionFailedException {
		JSONObject j = this.createJson(message, signature_message);

		for (Map.Entry<String, Server> entry : this.servers.entrySet()) {
			// TODO: coisa feia
			Server s = entry.getValue();
			Response response = s.getTarget().path(String.format("/Server/Register")).request()
					.accept(MediaType.APPLICATION_JSON)
					.post(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));

			checkStatus(response);
		}
	}

	public void put(String message, byte[] signature_message) {
		JSONObject j = this.createJson(message, signature_message);

		for (Map.Entry<String, Server> entry : this.servers.entrySet()) {
			// TODO: coisa feia
			Server s = entry.getValue();
			Response response = s.getTarget().path(String.format("/Server/Put")).request()
					.accept(MediaType.APPLICATION_JSON)
					.post(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));
			checkStatus(response);
		}
	}

	public Message get(String message, byte[] signature_message) throws ClassNotFoundException, IOException {
		JSONObject j = this.createJson(message, signature_message);
		String json = URLEncoder.encode(j.toJSONString(), "UTF-8");
		Message m = null;
		for (Map.Entry<String, Server> entry : this.servers.entrySet()) {
			// TODO: coisa feia
			Server s = entry.getValue();
			String aux = s.getTarget().path(String.format("/Server/Get/%s/", json)).request()
					.accept(MediaType.APPLICATION_JSON).get(String.class);
			m = (Message) CryptoFunctions.desSerialize(aux);
		}
		return m;
	}

	@SuppressWarnings("unchecked")
	private JSONObject createJson(String message, byte[] signature_message) {
		JSONObject j = new JSONObject();
		j.put("message", message);
		j.put("messageSignature", new String(signature_message));
		return j;
	}

	private static void checkStatus(Response res) {
		if (res.getStatus() == BAD_REQUEST)
			throw new BadRequestException();
		if (res.getStatus() != OK)
			throw new ConectionFailedException();
	}

}
