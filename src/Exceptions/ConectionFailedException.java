/**
 * 
 */
package Exceptions;

/**
 * @author paulo
 *
 */
public class ConectionFailedException extends RuntimeException {

	static final long serialVersionUID = 0L;

	public ConectionFailedException() {
		super();
	}

	public ConectionFailedException(String message) {
		super(message);
	}

}
