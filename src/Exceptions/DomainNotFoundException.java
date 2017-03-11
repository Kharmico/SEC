/**
 * 
 */
package Exceptions;

/**
 * @author paulo
 *
 */
public class DomainNotFoundException extends RuntimeException {

	static final long serialVersionUID = 0L;

	public DomainNotFoundException() {
		super();
	}

	public DomainNotFoundException(String message) {
		super(message);
	}
}
