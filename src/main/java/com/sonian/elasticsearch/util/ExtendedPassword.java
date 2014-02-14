package com.sonian.elasticsearch.util;

import com.sonian.elasticsearch.http.jetty.security.ExtendedCredential;
import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.security.Password;

/**
 * @author michal.michalski@boxever.com
 */
public class ExtendedPassword extends Password {

	public ExtendedPassword(String password) {
		super(password);
	}

	public static void main(String[] arg)
	{
		if (arg.length != 1 && arg.length != 2)
		{
			System.err.println("Usage - java com.sonian.elasticsearch.util.ExtendedPassword [<user>] <password>");
			System.err.println("If the password is ?, the user will be prompted for the password");
			System.exit(1);
		}
		String p = arg[arg.length == 1 ? 0 : 1];
		Password pw = new Password(p);
		System.err.println(pw.toString());
		System.err.println(obfuscate(pw.toString()));
		System.err.println(Credential.MD5.digest(p));
		System.err.println(ExtendedCredential.SHA.digest(p));
		if (arg.length == 2) System.err.println(Credential.Crypt.crypt(arg[0], pw.toString()));
	}
}
