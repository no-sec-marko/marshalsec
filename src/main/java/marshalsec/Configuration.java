package marshalsec;

import marshalsec.gadgets.GadgetType;
import org.apache.commons.lang3.StringUtils;

/**
 * @author marko
 * @version 1.0.0.
 * @date 21.08.2017
 */
public class Configuration {

	private String codebase;

	private String codebaseClass;

	private String JNDIUrl;

	private String executable;

	private EscapeType escapeType;

	private boolean test;

	private boolean all;

	private boolean verbose;

	private GadgetType gadgetType;

	private Configuration(ConfigurationBuilder builder) {

		this.codebase = builder.codebase;

		this.codebaseClass = builder.codebaseClass;

		this.JNDIUrl = builder.JNDIUrl;

		this.executable = builder.executable;

		this.escapeType = builder.escapeType;

		this.test = builder.test;

		this.all = builder.all;

		this.verbose = builder.verbose;

		this.gadgetType = builder.gadgetType;
	}

	public String getCodebase() {
		return codebase;
	}

	public String getCodebaseClass() {
		return codebaseClass;
	}

	public String getJNDIUrl() {
		return JNDIUrl;
	}

	public String getExecutable() {
		return executable;
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

	public String getPayloadByPrefix(final String prefix) {
		switch (prefix) {
			case "codebase":
				return getCodebase();
			case "codebaseClass":
				return getCodebaseClass();
			case "jndiUrl":
				return getJNDIUrl();
			case "exec":
				return getExecutable();
			default:
				return "";
		}
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
			return this;
		}

		public ConfigurationBuilder codebaseClass(String codebaseClass) {
			if (StringUtils.isBlank(codebaseClass)) {
				throw new IllegalArgumentException("CodebaseClass must not be Blank");
			}

			this.codebaseClass = String.format("{exploit.codebaseClass:%s}", codebaseClass);
			return this;
		}

		public ConfigurationBuilder JNDIUrl(String JNDIUrl) {
			if (StringUtils.isBlank(JNDIUrl)) {
				throw new IllegalArgumentException("JNDIUrl must not be Blank");
			}

			this.JNDIUrl = String.format("{exploit.jndiUrl:%s}", JNDIUrl);
			return this;
		}

		public ConfigurationBuilder executable(String executable) {
			if (StringUtils.isBlank(executable)) {
				throw new IllegalArgumentException("executable must not be Blank");
			}

			this.executable = String.format("{exploit.exec:%s}", executable);
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
