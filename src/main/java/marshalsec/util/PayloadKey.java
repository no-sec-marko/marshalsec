package marshalsec.util;

/**
 * @author marko
 * @version 1.0.0.
 * @date 10.09.2017
 */
public enum PayloadKey {

	CMD("cmd"), // {exploit.exec:/usr/bin/gedit}

	ARGS("args..."), // "tmp/foo"

	HOST("host"), // rmi interface

	PORT("port"), // rmi interface

	JNDIURL("jndiUrl"), // {exploit.jndiUrl:ldap://localhost:1389/obj}

	SERVICECODEBASE("service_codebase"), // {exploit.codebase:http://localhost:8080/}

	CODEBASE("codebase"), // {exploit.codebase:http://localhost:8080/}

	CLASSNAME("classname"), // {exploit.codebaseClass:Exploit}

	CODECLASS("class"); // {exploit.codebaseClass:Exploit}

	private final String payload;

	/**
	 * private constructor
	 */
	PayloadKey(final String value) {
		this.payload = value;
	}

	/**
	 * Get {@link PayloadKey} as string
	 *
	 * @return payload
	 */
	@Override
	public String toString() {
		return this.payload;
	}

	public static PayloadKey fromString(String value) {

		for (PayloadKey m : PayloadKey.values()) {

			if (m.payload.equalsIgnoreCase(value)) {
				return m;
			}
		}

		return null;
	}
}
