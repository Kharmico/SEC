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
//	public static final int OK = 200;
//	public static final int BAD_REQUEST = 400;

	// para teste usamos um vvalor random para identificar o dispositivo na
	// pratica deveria ser um ip adress
	// public ClientConnections(String[] urls) {
	// this.servers = new HashMap<String, Server>();
	// for (int i = 0; i < urls.length; i++) {
	// this.servers.put(urls[i], new ServerClass(urls[i]));
	// }
	//
	// }
	// public Map<String,Server> getServers(){
	// return this.servers;
	// }

	public static Response register(WebTarget target, String message, byte[] signature_message)
			throws ConectionFailedException {
		JSONObject j = ClientConnections.createJson(message, signature_message);
		return target.path(String.format("/Server/Register")).request().accept(MediaType.APPLICATION_JSON)
				.post(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));
	}

	public static Response put(WebTarget target, String message, byte[] signature_message) {
		JSONObject j = ClientConnections.createJson(message, signature_message);

		return target.path(String.format("/Server/Put")).request().accept(MediaType.APPLICATION_JSON)
				.post(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));

	}

	public static JSONObject get(WebTarget target, String message, byte[] signature_message)
			throws ClassNotFoundException, IOException {
		JSONObject j = ClientConnections.createJson(message, signature_message);
		String json = URLEncoder.encode(j.toJSONString(), "UTF-8");
		j = target.path(String.format("/Server/Get/%s/", json)).request().accept(MediaType.APPLICATION_JSON).get(JSONObject.class);
		return j;
	}

	@SuppressWarnings("unchecked")
	private static JSONObject createJson(String message, byte[] signature_message) {
		JSONObject j = new JSONObject();
		j.put("message", message);
		j.put("messageSignature", new String(signature_message));
		return j;
	}

//	private static void checkStatus(Response res) {
//		if (res.getStatus() == BAD_REQUEST)
//			throw new BadRequestException();
//		if (res.getStatus() != OK)
//			throw new ConectionFailedException();
//	}

}
