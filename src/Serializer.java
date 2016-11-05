import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Serializer
{
    public static byte[] serialize(Object obj) throws Exception
    {
        try(ByteArrayOutputStream b = new ByteArrayOutputStream())
        {
            try(ObjectOutputStream o = new ObjectOutputStream(b))
            {
                o.writeObject(obj);
            }
            catch (Exception e)
            {
              System.out.println("An Error Has Occured");
              return null;
            }
            return b.toByteArray();
        }
        catch (Exception e)
        {
          System.out.println("An Error Has Occured");
          return null;
        }
    }

    public static Object deserialize(byte[] bytes) throws Exception
    {
        try(ByteArrayInputStream b = new ByteArrayInputStream(bytes))
        {
            try(ObjectInputStream o = new ObjectInputStream(b))
            {
                return o.readObject();
            }
            catch (Exception e)
            {
              System.out.println("An Error Has Occured");
              return null;
            }
        }
        catch (Exception e)
        {
          System.out.println("An Error Has Occured");
          return null;
        }
    }

}
