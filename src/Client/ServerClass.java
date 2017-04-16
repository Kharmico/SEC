package Client;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.client.ClientConfig;

public class ServerClass implements Server {
	private String url;
	private long time;
	private int TIMEOUT = 120 * 1000;
	private WebTarget target;

	public ServerClass(String url) {
		this.url = url;
		this.updateTime();
		ClientConfig config = new ClientConfig();
		Client client = ClientBuilder.newClient(config);
		this.target = client.target(UriBuilder.fromUri(url).build());
	}

	public WebTarget getTarget() {
		return this.target;
	}

	public String getUrl() {
		return this.url;
	}

	public void updateTime() {
		this.time = System.currentTimeMillis();
	}

	/**
	 * 
	 * @return true if server emited a heartbeat in the last timeout
	 */
	public boolean isAlive() {
		return (System.currentTimeMillis() - this.time) < TIMEOUT;
	}

	public long getTime() {
		return this.time;
	}

}
