/**
 * 
 */
package Client;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

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

import Exceptions.ConectionFailedException;

/**
 * @author paulo
 *
 */
public final class ClientConnections {

	public static final String SERVER_URL = "http://localhost:9000";
	public static final int OK = 200;
	public static final int BAD_REQUEST = 400;

	private WebTarget target;
	private Client client;

	public ClientConnections() {
		ClientConfig config = new ClientConfig();
		client = ClientBuilder.newClient(config);
		target = client.target(UriBuilder.fromUri(SERVER_URL).build());
	}

	@SuppressWarnings("unchecked")
	public void register(String pubKey) throws ConectionFailedException {
		JSONObject j = new JSONObject();
		j.put("pubKey", pubKey);
		WebTarget target = this.target.path(String.format("/Server/Register"));
		Response response = target.request().accept(MediaType.APPLICATION_JSON)
				.post(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));

		checkStatus(response);
	}

	@SuppressWarnings("unchecked")
	public void put(String pubKey, String domain, String username, String password) {
		JSONObject j = new JSONObject();
		j.put("pubKey", pubKey);
		j.put("domain", domain);
		j.put("username", username);
		j.put("password", password);
		WebTarget target = this.target.path(String.format("/Server/Put"));
		Response response = target.request().accept(MediaType.APPLICATION_JSON)
				.put(Entity.entity(j.toJSONString(), MediaType.APPLICATION_JSON));
		checkStatus(response);
	}

	@SuppressWarnings("unchecked")
	public String get(String pubKey, String domain, String username) throws UnsupportedEncodingException {
		System.out.println("domain no client " + domain);
		JSONObject j = new JSONObject();
		j.put("pubKey", pubKey);
		j.put("domain", domain);
		j.put("username", username);
		String json = URLEncoder.encode(j.toJSONString(), "UTF-8");
		WebTarget target = this.target.path(String.format("/Server/Get/%s/", json));
		String response = target.request().accept(MediaType.APPLICATION_JSON).get(String.class);
		return response;
	}

	private void checkStatus(Response res) {
		if (res.getStatus() == BAD_REQUEST) 
			throw new BadRequestException();
		if(res.getStatus()!=OK)
			throw new ConectionFailedException();
	}

}
