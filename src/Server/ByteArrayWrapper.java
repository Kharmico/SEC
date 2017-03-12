package Server;

import java.io.Serializable;
import java.util.Arrays;

public  class ByteArrayWrapper implements Serializable
{
    /**
	 * Base64.getEncoder().encode(toEncode);
	 */
	private static final long serialVersionUID = 1L;
	private final byte[] data;

    public ByteArrayWrapper(byte[] data)
    {
        if (data == null)
        {
            throw new NullPointerException();
        }
        this.data = data;
    }

    public byte[] getData(){
    	return this.data;
    }
    
    @Override
    public Object clone(){
    	return new ByteArrayWrapper(this.data);
    }
    @Override
    public boolean equals(Object other)
    {
        if (!(other instanceof ByteArrayWrapper))
        {
            return false;
        }
        return Arrays.equals(data, ((ByteArrayWrapper)other).getData());
     
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(data);
    }
}