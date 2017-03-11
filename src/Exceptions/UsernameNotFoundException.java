package Exceptions;

public class UsernameNotFoundException extends RuntimeException {

	static final long serialVersionUID = 0L;

	public UsernameNotFoundException() {
		super();
	}

	public UsernameNotFoundException(String message) {
		super(message);
	}
}

