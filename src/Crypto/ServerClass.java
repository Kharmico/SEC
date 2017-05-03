package Crypto;

import java.security.PublicKey;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.client.ClientConfig;

public class ServerClass implements IServer {
	private String url;
	private long time;
	private int TIMEOUT = 120 * 1000;
	private WebTarget target;
	private PublicKey pubKey;

	public ServerClass(String url) {
		this.url = url;
		this.updateTime();
		ClientConfig config = new ClientConfig();
		Client client = ClientBuilder.newClient(config);
		this.target = client.target(UriBuilder.fromUri(url).build());
		this.pubKey=null;
	}
	
	public void setPubKey(PublicKey key){
		this.pubKey=key;
	}
	
	@Override
	public PublicKey getPubKey() {
		return this.pubKey;
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
