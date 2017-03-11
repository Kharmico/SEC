/**
 * 
 */
package Exceptions;

/**
 * @author paulo
 *
 */
public class UserAlreadyRegisteredException extends RuntimeException {

	static final long serialVersionUID = 0L;

	public UserAlreadyRegisteredException() {
		super();
	}

	public UserAlreadyRegisteredException(String message) {
		super(message);
	}
}