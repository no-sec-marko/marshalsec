package marshalsec;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import marshalsec.gadgets.GadgetType;
import marshalsec.util.PayloadKey;
import org.apache.commons.lang3.StringUtils;

/**
 * @author marko
 * @version 1.0.0.
 * @date 21.08.2017
 */
public class Configuration {

	private EscapeType escapeType;

	private boolean test;

	private boolean all;

	private boolean verbose;

	private GadgetType gadgetType;

	private Map<PayloadKey, String> payloads = new HashMap<>();

	private Configuration(ConfigurationBuilder builder) {

		this.payloads.put(PayloadKey.CMD, builder.executable);

		this.payloads.put(PayloadKey.ARGS, builder.execArgs);

		this.payloads.put(PayloadKey.CODECLASS, builder.codebaseClass);

		this.payloads.put(PayloadKey.JNDIURL, builder.JNDIUrl);

		this.payloads.put(PayloadKey.CLASSNAME, builder.className);

		this.payloads.put(PayloadKey.HOST, builder.host);

		this.payloads.put(PayloadKey.PORT, builder.port);

		this.payloads.put(PayloadKey.CODEBASE, builder.codebase);

		this.payloads.put(PayloadKey.SERVICECODEBASE, builder.serviceCodeBase);

		this.escapeType = builder.escapeType;

		this.test = builder.test;

		this.all = builder.all;

		this.verbose = builder.verbose;

		this.gadgetType = builder.gadgetType;
	}

	public EscapeType getEscapeType() {
		return escapeType;
	}

	public boolean isTest() {
		return test;
	}

	public boolean isAll() {
		return all;
	}

	public boolean isVerbose() {
		return verbose;
	}

	public GadgetType getGadgetType() {
		return gadgetType;
	}

	public Map<PayloadKey, String> getPayloads() {
		return payloads;
	}

	public static ConfigurationBuilder create() {
		return new ConfigurationBuilder();
	}

	/**
	 * Builder for the {@link Configuration} object. Contains default values.
	 */
	public static class ConfigurationBuilder {

		private String codebase = "{exploit.codebase:http://localhost:8080/}";

		private String codebaseClass = "{exploit.codebaseClass:Exploit}";

		private String JNDIUrl = "{exploit.jndiUrl:ldap://localhost:1389/obj}";

		private String executable = "{exploit.exec:/usr/bin/gedit}";

		private String execArgs = "args...";

		private String port = "1099";

		private String host = "localhost";

		private String serviceCodeBase = "{exploit.codebase:http://localhost:8080/}";

		private String className = "{exploit.codebaseClass:Exploit}";

		private EscapeType escapeType = EscapeType.NONE;

		private boolean test = false;

		private boolean all = true;

		private boolean verbose = false;

		private GadgetType gadgetType = null;

		public Configuration build() {
			return new Configuration(this);
		}

		public ConfigurationBuilder codebase(String codebase) {

			if (StringUtils.isBlank(codebase)) {
				throw new IllegalArgumentException("Codebase must not be Blank");
			}

			this.codebase = String.format("{exploit.codebase:%s}", codebase);

			this.serviceCodeBase = String.format("{exploit.codebase:%s}", codebase);

			return this;
		}

		public ConfigurationBuilder codebaseClass(String codebaseClass) {
			if (StringUtils.isBlank(codebaseClass)) {
				throw new IllegalArgumentException("CodebaseClass must not be Blank");
			}

			this.codebaseClass = String.format("{exploit.codebaseClass:%s}", codebaseClass);

			this.className = String.format("{exploit.codebaseClass:%s}", codebaseClass);

			return this;
		}

		public ConfigurationBuilder JNDIUrl(URI JNDIUrl) {
			if (JNDIUrl == null) {
				throw new IllegalArgumentException("JNDIUrl must not be empty");
			}

			this.JNDIUrl = String.format("{exploit.jndiUrl:%s}", JNDIUrl.toString());

			if (JNDIUrl.getScheme().equals("rmi")) {
				this.port = String.valueOf(JNDIUrl.getPort());
				this.host = JNDIUrl.getHost() + JNDIUrl.getHost();
			}

			return this;
		}

		public ConfigurationBuilder executable(String executable, String args) {
			if (StringUtils.isEmpty(executable) && args != null) {
				throw new IllegalArgumentException("executable and args must not be empty");
			}

			this.executable = String.format("{exploit.exec:%s}", executable);

			this.execArgs = String.format("{exploit.execargs:%s}", args);

			return this;
		}

		public ConfigurationBuilder escapeType(EscapeType escapeType) {
			this.escapeType = escapeType;
			return this;
		}

		public ConfigurationBuilder gadgetType(GadgetType gadgetType) {
			this.gadgetType = gadgetType;
			return this;
		}

		public ConfigurationBuilder test(boolean test) {
			this.test = test;
			return this;
		}

		public ConfigurationBuilder all(boolean all) {
			this.all = all;
			return this;
		}

		public ConfigurationBuilder verbose(boolean verbose) {
			this.verbose = verbose;
			return this;
		}
	}
}
