package marshalsec;

import java.util.ArrayList;
import java.util.List;
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

	public List<String> allPayloads() throws Exception {

		List<String> payload = new ArrayList<>();

		payload.addAll(this.payload(new JsonIO()).values());

		payload.addAll(this.payload(new Kryo()).values());

		payload.addAll(this.payload(new KryoAltStrategy()).values());

		payload.addAll(this.payload(new Jackson()).values());

		payload.addAll(this.payload(new JYAML()).values());

		payload.addAll(this.payload(new SnakeYAML()).values());

		payload.addAll(this.payload(new YAMLBeans()).values());

		payload.addAll(this.payload(new Castor()).values());

		payload.addAll(this.payload(new Burlap()).values());

		payload.addAll(this.payload(new Hessian()).values());

		payload.addAll(this.payload(new BlazeDSAMF0()).values());

		payload.addAll(this.payload(new BlazeDSAMF3()).values());

		payload.addAll(this.payload((new BlazeDSAMFX())).values());

		payload.addAll(this.payload(new Red5AMF0()).values());

		payload.addAll(this.payload(new Red5AMF3()).values());

		payload.addAll(this.payload(new Java()).values());

		payload.addAll(this.payload(new XStream()).values());

		return payload;
	}


}
