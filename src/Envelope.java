import java.util.ArrayList;


public class Envelope implements java.io.Serializable {

	/**
	 *
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();

	public Envelope(String text)
	{
		msg = text;
	}

	public String getMessage()
	{
		return msg;
	}

	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}

	public byte[] getCounter()
	{
		return (byte[])objContents.get(objContents.size()-2);
	}

	public String getHMAC()
	{
		return (String)objContents.get(objContents.size()-1);
	}

	public void addObject(Object object)
	{
		objContents.add(object);
	}

}
