package Client;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;

import Crypto.CryptoFunctions;
import Crypto.IServer;
import Crypto.KeyStoreFunc;
import Crypto.Message;
import Crypto.Password;
import Crypto.ServerClass;
import Exceptions.NullByzantineQuorumException;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.security.auth.DestroyFailedException;
import javax.ws.rs.core.Response;

import org.json.simple.JSONObject;

//Class com cryptografica
public class ClientManager implements PasswordManager {
	private static final String CLIENT_PAIR_ALIAS = "clientPair";
	private static final String CERT_PATH = System.getProperty("user.dir") + "\\Resources\\serversec%s.cer";
	private int f = 1;
	// private long wts = 0;
	private long rid = 0;
	private static List<String> ackList;
	private static ArrayList<Password> readList;

	private KeyStore ks = null;
	PasswordProtection ksPassword = null;
	int bitLength = 1024;
	SecureRandom rnd = new SecureRandom();
	private String deviceId;
	private Map<String, IServer> servers;

	public ClientManager(String[] urls) {
		this.servers = new HashMap<String, IServer>();
		for (int i = 0; i < urls.length; i++) {
			this.servers.put(urls[i], new ServerClass(urls[i]));
		}
		// assume that device id is uniq
		Random r = new Random();
		int Low = 1;
		int High = 10000;
		Integer result = r.nextInt(High - Low) + Low;
		ackList = new ArrayList<String>(servers.size());
		readList = new ArrayList<Password>(servers.size());
		deviceId = new String(Base64.getEncoder().encode(result.toString().getBytes()));
		// CryptoFunctions.setJcePolicy();
	}

	/*
	 * Specification: initializes the library before its first use. This method
	 * should receive a reference to a key store that must contain the private
	 * and public key of the user, as well as any other parameters needed to
	 * access this key store (e.g., its password) and to correctly initialize
	 * the cryptographic primitives used at the client side. These keys
	 * maintained by the key store will be the ones used in the following
	 * session of commands issued at the client side, until a close() function
	 * is called.
	 */
	@Override
	public void init(KeyStore ks, char[] ksPassword) throws Exception {
		this.ks = ks;
		this.ksPassword = new PasswordProtection(ksPassword);
		for (IServer s : servers.values()) {
			URI u = new URI(s.getUrl());
			u.getPort();
			System.out.println("URI AND PORT: " + u + " " + u.getPort());
			PublicKey serverPubKey = KeyStoreFunc.getPublicKeyCertificate(String.format(CERT_PATH, u.getPort()));
			s.setPubKey(serverPubKey);
		}

	}

	/*
	 * Specification: registers the user on the server, initializing the
	 * required data structures to securely store the passwords.
	 */
	@Override
	public void register_user() throws Exception {

		byte[] nonce = CryptoFunctions.generateNonce();
		// Get the public key to send!!!
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		byte[] hash_nonce = CryptoFunctions.getHashMessage(nonce);
		Message m = new Message(pubk, hash_nonce, deviceId);
		String serialized_message = CryptoFunctions.serialize(m);
		byte[] signed_message = CryptoFunctions.sign_data(serialized_message.getBytes(), privk);
		for (IServer s : servers.values()) {
			// TODO: check acks to know that we have enough servers
			ClientConnections.register(s, serialized_message, signed_message);
		}

	}

	/*
	 * Specification: stores the triple (domain, username, password) on the
	 * server. This corresponds to an insertion if the (domain, username) pair
	 * is not already known by the server, or to an update otherwise.
	 */
	@Override
	public void save_password(byte[] domain, byte[] username, byte[] password) throws Exception {

		// byte[] nonce = CryptoFunctions.generateNonce();
		// Get the public key to send!!!
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		byte[] cypher_p = CryptoFunctions.encrypt_data_asymmetric(password, pubk);
		String salt = this.getSalt();

		// wts++;
		byte[] hash_d = CryptoFunctions.getHashMessage((new String(domain) + salt).getBytes());
		byte[] hash_u = CryptoFunctions.getHashMessage((new String(username) + salt).getBytes());
		byte[] pduSignature = CryptoFunctions
				.sign_data((new String(hash_d) + new String(hash_u) + new String(cypher_p)).getBytes(), privk);
		Password pw = new Password(hash_d, hash_u, cypher_p, pduSignature);
		sendMsgServers(pubk, privk, hash_d, hash_u, pw, deviceId);
	}

	/*
	 * Specification: retrieves the password associated with the given (domain,
	 * username) pair. The behavior of what should happen if the (domain,
	 * username) pair does not exist is unspecified.
	 */
	@Override
	public byte[] retrieve_password(byte[] domain, byte[] username) throws Exception {

		byte[] nonce = CryptoFunctions.generateNonce();
		// Get the public key to send!!!
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		String salt = this.getSalt();

		rid++;
		byte[] hash_d = CryptoFunctions.getHashMessage((new String(domain) + salt).getBytes());
		byte[] hash_u = CryptoFunctions.getHashMessage((new String(username) + salt).getBytes());
		Message m = new Message(pubk, hash_d, hash_u, nonce, deviceId, rid);
		String serialized_message = CryptoFunctions.serialize(m);
		byte[] signed_message = CryptoFunctions.sign_data(serialized_message.getBytes(), privk);
		Password pw = null;
		for (IServer s : servers.values()) {
			m = ClientConnections.get(s, serialized_message, signed_message);
			if (validMessage(m)) {
				pw = m.getPassword();
				if (rid == m.getTimeStamp()) {
					if (CryptoFunctions.verifySignature(
							(new String(hash_d) + new String(hash_u) + new String(pw.getPassword())).getBytes(),
							pw.getPasswordSignature(), pubk)) {
						System.out.println("VERIFIED SIGNATURE WITH SUCCESS");
						readList.add(pw);
					}
				}
			}
		}
		Password pwAux = null;
		if (readList.size() > ((servers.size() + f) / 2)) {
			pwAux = mostFrequent(readList);
			// int passwordAux = 0;
			// for (Password password : readList) {
			// if (password != null)
			// passwordAux++;
			// else
			// System.out.println("PASSWORD PASSWORD IS NULL");
			// }
			//
			// System.out.println("PASSWORDAUX VALUE (counter): " +
			// passwordAux);
			//
			// Password pwAux = null;
			// if (passwordAux > ((servers.size() + f) / 2)) {
			// long tsAux = 0;
			// for (Password password : readList) {
			// if (password != null) {
			//
			//// if (tsAux < password.getTimeStamp()) {
			//// tsAux = password.getTimeStamp();
			//// pwAux = password;
			//// }
			// }
			// }
			readList.clear();

			nonce = CryptoFunctions.generateNonce();
			hash_d = pwAux.getDomain();
			hash_u = pwAux.getUsername();
			// long pwWts = pwAux.getTimeStamp();

			// sendMsgServers(pubk, privk, hash_d, hash_u, pwAux, deviceId);

			return CryptoFunctions.decrypt_data_asymmetric(pwAux.getPassword(), privk);
		}

		System.out.println("PWAUX VALUE (in case of null): " + pwAux);
		throw new NullByzantineQuorumException("Not enough correct servers!");

	}

	@Override
	public void close() throws DestroyFailedException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {

		KeyStoreFunc.safeStore(ks, ksPassword.getPassword());
		ksPassword.destroy();
		// concludes the current session of commands with the client library.

	}

	private String getSalt() throws KeyStoreException {
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		String aux = Base64.getEncoder().encodeToString(pubk.getEncoded());
		return (String) aux.subSequence(0, Math.min(aux.length(), 10));
	}

	private void sendMsgServers(PublicKey pubk, PrivateKey privk, byte[] hash_d, byte[] hash_u, Password pw,
			String deviceId) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		byte[] nonce = CryptoFunctions.generateNonce();
		Message m = new Message(pubk, hash_d, hash_u, pw, nonce, deviceId);
		String serialized_message = CryptoFunctions.serialize(m);
		byte[] signed_message = CryptoFunctions.sign_data(serialized_message.getBytes(), privk);

		ackList = new LinkedList<String>();
		assert (ackList.size() == servers.size());
		for (IServer s : servers.values()) {
			Message r = ClientConnections.put(s, serialized_message, signed_message);

			if (r.getStatus() == 200)
				ackList.add("ack");
			System.out.println("GETTING STATUS STATUS: " + r.getStatus());
		}
		if (ackList.size() > ((servers.size() + f) / 2))
			ackList.clear();
		else {
			ackList.clear();
			throw new NullByzantineQuorumException("Not enough correct servers!");
		}
	}

	private boolean validMessage(Message m) {
		return m != null && m.getPassword() != null && m.getNounce() != null;
	}

	private Password mostFrequent(List<Password> passwords) {
		Password mf = new Password();
		int freq = 0;
		for (Password p : passwords) {
			int aux = Collections.frequency(passwords, p);
			if (aux > freq) {
				freq = aux;
				mf = p;
			}
		}
		return mf;
	}

}
