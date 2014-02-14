package com.sonian.elasticsearch.http.jetty.security;

import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.security.Password;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.jasypt.util.password.StrongPasswordEncryptor;

/**
 *
 * @author michal.michalski@boxever.com
 */
public abstract class ExtendedCredential extends Credential {

	private static final Logger LOG = Log.getLogger(ExtendedCredential.class);

	private static final long serialVersionUID = -2230551052712181582L;

	public static Credential getCredential(String credential)
	{
		if (credential.startsWith(SHA.__TYPE)) return new SHA(credential);
		return Credential.getCredential(credential);
	}

	public static class SHA extends ExtendedCredential
	{
		private static final long serialVersionUID = -1027492276665442310L;

		public static final String __TYPE = "SHA:";

		private final String _cooked;

		SHA(String cooked)
		{
			_cooked = cooked.startsWith(SHA.__TYPE) ? cooked.substring(__TYPE.length()) : cooked;
		}

		@Override
		public boolean check(Object credentials)
		{
			if (credentials instanceof char[])
				credentials=new String((char[])credentials);
			if (!(credentials instanceof String) && !(credentials instanceof Password))
				LOG.warn("Can't check " + credentials.getClass() + " against " + __TYPE);

			String passwd = credentials.toString();
			StrongPasswordEncryptor spe = new StrongPasswordEncryptor();
			return spe.checkPassword(passwd, _cooked);
		}

		public static String digest(String pw)
		{
			StrongPasswordEncryptor spe = new StrongPasswordEncryptor();
			return __TYPE + spe.encryptPassword(pw);
		}
	}
}
