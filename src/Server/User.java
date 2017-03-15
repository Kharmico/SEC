/**
 * 
 */
package Server;

import java.io.Serializable;
import java.security.Key;
import java.util.Hashtable;
import java.util.Map;

import Exceptions.*;

/**
 * @author paulo
 *
 */
public class User implements Serializable{
	private static final long serialVersionUID = 1L;
	private ByteArrayWrapper pubKey;
//domain /user/pass
	private Map<ByteArrayWrapper, Hashtable<ByteArrayWrapper, ByteArrayWrapper>> userTriples;

	public User(ByteArrayWrapper pubKey) {
		this.pubKey = pubKey;
		this.userTriples = new Hashtable<ByteArrayWrapper,Hashtable<ByteArrayWrapper, ByteArrayWrapper>>();
	}

	public ByteArrayWrapper getPubKey() {
		return this.pubKey;
	}

	public void put(byte[] domain, byte[] username, byte[] password) {
		ByteArrayWrapper d = new ByteArrayWrapper(domain);
		ByteArrayWrapper u = new ByteArrayWrapper(username);
		ByteArrayWrapper p = new ByteArrayWrapper(password);
		
		Hashtable<ByteArrayWrapper, ByteArrayWrapper> userNames = this.userTriples.get(d);
		if (userNames == null)
			userNames = new Hashtable<ByteArrayWrapper, ByteArrayWrapper>();
		userNames.put(u, p);
		this.userTriples.put(d,userNames);
	}

	public byte[] get(byte[] domain, byte[] username) throws UsernameNotFoundException, DomainNotFoundException {
		ByteArrayWrapper d = new ByteArrayWrapper(domain);
		ByteArrayWrapper u = new ByteArrayWrapper(username);
		Hashtable<ByteArrayWrapper, ByteArrayWrapper> userNames = this.userTriples.get(d);
		if (userNames == null)
			throw new DomainNotFoundException();
		ByteArrayWrapper aux =userNames.get(u);
		if (aux==null)
			throw new UsernameNotFoundException();
		
		return aux.getData();

	}
	
	public Map<ByteArrayWrapper, Hashtable<ByteArrayWrapper, ByteArrayWrapper>> getTriples(){
		return this.userTriples;
	}

}
