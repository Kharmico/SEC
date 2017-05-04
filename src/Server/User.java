/**
 * 
 */
package Server;

import java.io.Serializable;
import java.security.Key;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import Crypto.Password;
import Exceptions.*;

/**
 * @author paulo
 *
 */
public class User implements Serializable {
	private static final long serialVersionUID = 1L;
	private ByteArrayWrapper pubKey;
	// domain /user/pass
	private Map<ByteArrayWrapper, Hashtable<ByteArrayWrapper, Password>> userTriples;
	private List<Password> history;

	public User(ByteArrayWrapper pubKey) {
		this.pubKey = pubKey;
		this.history = new LinkedList<Password>();
		this.userTriples = new Hashtable<ByteArrayWrapper, Hashtable<ByteArrayWrapper, Password>>();
	}

	public ByteArrayWrapper getPubKey() {
		return this.pubKey;
	}

	public void put(byte[] domain, byte[] username, Password password) {
		ByteArrayWrapper d = new ByteArrayWrapper(domain);
		ByteArrayWrapper u = new ByteArrayWrapper(username);
		// ByteArrayWrapper p = new ByteArrayWrapper(password);

		Hashtable<ByteArrayWrapper, Password> userNames = this.userTriples.get(d);
		if (userNames == null) {
			userNames = new Hashtable<ByteArrayWrapper, Password>();

		}

		if (password.equals(userNames.get(u))) {
			if (password.getTimeStamp() > userNames.get(u).getTimeStamp()
					|| (password.getTimeStamp() == userNames.get(u).getTimeStamp()
							&& (password.getDeviceId().compareTo(userNames.get(u).getDeviceId())) > 0)) {
				userNames.put(u, password);
				this.userTriples.put(d, userNames);
				this.history.add(password);
			}
		} else {
			userNames.put(u, password);
			this.userTriples.put(d, userNames);
			this.history.add(password);
		}
	}

	public List<Password> getPasswords() {
		return this.history;
	}

	public Password get(byte[] domain, byte[] username) throws UsernameNotFoundException, DomainNotFoundException {
		ByteArrayWrapper d = new ByteArrayWrapper(domain);
		ByteArrayWrapper u = new ByteArrayWrapper(username);
		Hashtable<ByteArrayWrapper, Password> userNames = this.userTriples.get(d);
		if (userNames == null)
			throw new DomainNotFoundException();
		Password aux = userNames.get(u);
		if (aux == null)
			throw new UsernameNotFoundException();
		return aux;
	}

	public Map<ByteArrayWrapper, Hashtable<ByteArrayWrapper, Password>> getTriples() {
		return this.userTriples;
	}

}
