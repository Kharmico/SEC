/**
 * 
 */
package Exceptions;

/**
 * @author paulo
 *
 */
public class InvalidSignatureException extends RuntimeException {

	static final long serialVersionUID = 0L;

	public InvalidSignatureException() {
		super();
	}

	public InvalidSignatureException(String message) {
		super(message);
	}

}
