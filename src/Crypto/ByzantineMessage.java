package Crypto;

import java.security.PublicKey;

public class ByzantineMessage {
	
	public static Message changeClient(Message original,PublicKey pk){
		//tenta mudar o autor da mensagem, caso a mensagem tenha sido enviado por um cliente
		// nao funciona de funcionar por causa da assinatura que o cliente faz, e pela password estar encriptado
		Message m = new Message();
		m=original;
		return m;
	}

}
