/**
 * 
 */
package Client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
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
import Crypto.IServer;
import Exceptions.ConectionFailedException;

/**
 * @author paulo
 *
 */
public class ClientConnections {

	public static Message register(IServer s, String message, byte[] signature_message) {
		return ClientConnections.connect(s, message, signature_message, "Register");

	}

	public static Message put(IServer s, String message, byte[] signature_message) {
		return ClientConnections.connect(s, message, signature_message, "Put");

	}

	public static Message get(IServer s, String message, byte[] signature_message) {
		return ClientConnections.connect(s, message, signature_message, "Get");
	}

	@SuppressWarnings("unchecked")
	private static JSONObject createJson(String message, byte[] signature_message) {
		JSONObject j = new JSONObject();
		j.put("message", message);
		j.put("messageSignature", new String(signature_message));
		return j;
	}

	private static Message connect(IServer s, String message, byte[] signature_message, String webResource) {
		Message m = new Message();
		m.setStatus(400);
		try {
			JSONObject j = ClientConnections.createJson(message, signature_message);

			String json = URLEncoder.encode(j.toJSONString(), "UTF-8");
			j = s.getTarget().path(String.format("/Server/%s/%s/", webResource, json)).request()
					.accept(MediaType.APPLICATION_JSON).get(JSONObject.class);
			String serialized_message = (String) j.get("message");
			byte[] signature = ((String) j.get("signature")).getBytes();

			if (CryptoFunctions.verifySignature(serialized_message.getBytes(), signature, s.getPubKey())) {
				m = ((Message) CryptoFunctions.desSerialize(serialized_message));
				CryptoFunctions.getHashMessage(m.getNounce());
				m.setStatus((int) j.get("status"));
				return m;
			}
		} catch (ConnectException e) {
			

		} catch (UnsupportedEncodingException e) {

		} catch (InvalidKeyException e) {

		} catch (SignatureException e) {

		} catch (NoSuchAlgorithmException e) {

		} catch (ClassNotFoundException e) {

		} catch (IOException e) {
			
		}catch(javax.ws.rs.ProcessingException e){
			

		}catch(Exception e){
			System.out.println("excepcao------------------------------");
			//e.printStackTrace();
		}
		return m;
	}
}
