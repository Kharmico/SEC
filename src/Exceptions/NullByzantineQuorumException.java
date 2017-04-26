package Exceptions;

public class NullByzantineQuorumException extends RuntimeException {
	static final long serialVersionUID = 0L;

	public NullByzantineQuorumException() {
		super();
	}

	public NullByzantineQuorumException(String message) {
		super(message);
	}
}
