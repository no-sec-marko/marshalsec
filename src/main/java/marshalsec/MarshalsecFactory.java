package marshalsec;

import java.util.Map;

/**
 * @author mawn
 * @version 1.0.0.
 * @date 21.08.2017
 */
public class MarshalsecFactory {

	private Configuration configuration;

	public MarshalsecFactory(Configuration configuration) {
		this.configuration = configuration;
	}

	public Map payload(MarshallerBase marshal) throws Exception {

		marshal.run(configuration);

		return marshal.getPayload();
	}


}
