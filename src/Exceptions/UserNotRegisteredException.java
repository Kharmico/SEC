/**
 * 
 */
package Exceptions;

/**
 * @author paulo
 *
 */
public class UserNotRegisteredException extends RuntimeException {

	static final long serialVersionUID = 0L;

	public UserNotRegisteredException() {
		super();
	}

	public UserNotRegisteredException(String message) {
		super(message);
	}
}