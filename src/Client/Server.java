package Client;

import java.security.PublicKey;

import javax.ws.rs.client.WebTarget;

public interface Server {
	/**
	 * 
	 * @return o url do servidor
	 */
	public String getUrl();

	/**
	 * actualiza o tempo do servidor
	 */
	public void updateTime();

	/**
	 * @return true se o servidor emitiu um heartbeat recentemente
	 */
	public boolean isAlive();

	/**
	 * @return tempo da ultima vez que o servidor enviou um heartbeat
	 */
	public long getTime();

	
	public WebTarget getTarget();
	
	public PublicKey getPubKey();
	
	public void setPubKey(PublicKey key);
}
