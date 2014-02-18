package com.sonian.elasticsearch.http.jetty.security;

import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.security.MappedLoginService;
import org.eclipse.jetty.server.UserIdentity;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.index.get.GetField;
import org.elasticsearch.indices.IndexMissingException;

import java.util.List;

import static org.elasticsearch.common.collect.Lists.newArrayList;

/**
 * @author drewr
 */
public class ESLoginService extends MappedLoginService {
    private volatile String authIndex;

    private volatile String authType;

    private volatile String passwordField = "password";

    private volatile String rolesField = "roles";

    private volatile int cacheTime = -1;

    private volatile long lastHashPurge;

    private volatile Client client;

	private static final ESLogger LOG = ESLoggerFactory.getLogger(ESLoginService.class.toString());

	public ESLoginService() {
	}

    public ESLoginService(String name) {
        setName(name);
	}

    public void setClient(Client client) {
        this.client = client;
    }

    public Client getClient() {
        return client;
    }

    public void setAuthIndex(String authIndex) {
        this.authIndex = authIndex;
    }

    public String getAuthIndex() {
        return authIndex;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public String getAuthType() {
        return authType;
    }

    public void setCacheTime(int cacheTime) {
        this.cacheTime = cacheTime;
    }

    public int getCacheTime() {
        return cacheTime;
    }

    public void setPasswordField(String passwordField) {
        this.passwordField = passwordField;
    }

    public String getPasswordField() {
        return passwordField;
    }

    public void setRolesField(String rolesField) {
        this.rolesField = rolesField;
    }

    public String getRolesField() {
        return rolesField;
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();
        if (authIndex == null) {
            throw new IllegalArgumentException("User realm " + getName() + " has not been  properly configured - missing authentication index");
        }
        if (authType == null) {
            throw new IllegalArgumentException("User realm " + getName() + " has not been  properly configured - missing authentication type");
        }
        lastHashPurge = 0;
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();
    }

    @Override
    public UserIdentity login(String username, Object credentials) {
		if (isUsersCacheOn()) {
			maybeInvalidateUsersCache();
        }

		return getUserIdentity(username, credentials);
    }

	private UserIdentity getUserIdentity(String username, Object credentials) {
		UserIdentity u = super.login(username, credentials);
		String message = u != null ? "authenticating user [{}]" : "did not find user [{}]";
		LOG.debug(message, username);
		return u;
	}

	private boolean isUsersCacheOn() {
		return cacheTime >= 0;
	}

	private void maybeInvalidateUsersCache() {
		long now = System.currentTimeMillis();

		if (shouldInvalidateUsersCache(now)) {
			invalidateUsersCache(now);
		}
	}

	private boolean shouldInvalidateUsersCache(long now) {
		return hasUsersCacheExpired(now) || cacheTime == 0;
	}

	private boolean hasUsersCacheExpired(long now) {
		return now - lastHashPurge > cacheTime;
	}

	private void invalidateUsersCache(long now) {
		_users.clear();
		lastHashPurge = now;
	}

	@Override
    public UserIdentity loadUser(String user) {
		LOG.debug("attempting to load user [{}]", user);
		try {
            GetResponse response = client.prepareGet(authIndex, authType, user)
                    .setFields(passwordField, rolesField)
                    .execute().actionGet();
            if (response.isExists()) {
				LOG.debug("user [{}] exists; looking for credentials...", user);
				return loadAcls(user, response);
            }
        } catch (IndexMissingException e) {
			LOG.warn("no auth index [{}]", authIndex);
        } catch (Exception e) {
			LOG.warn("error finding user [" + user + "] in [" + authIndex + "]", e);
        }
        return null;
    }

	private UserIdentity loadAcls(String user, GetResponse response) {
		Credential credential = maybeRetrieveCredential(user, response);
		String[] roles = getStringValues(response.getField(rolesField));
		return putUser(user, credential, roles);
	}

	private Credential maybeRetrieveCredential(String user, GetResponse response) {
		GetField passwordGetField = response.getField(passwordField);
		if (passwordGetField != null) {
			LOG.debug("user [{}] using password auth", user);
			return ExtendedCredential.getCredential((String) passwordGetField.getValue());
		}
		return null;
	}

	private String[] getStringValues(GetField field) {
        List<String> values = newArrayList();
        if (field != null) {
            for(Object value : field.getValues()) {
                if (field.getValue() instanceof Iterable) {
                    for(Object val : (Iterable) field.getValue()) {
                        values.add((String) val);
                    }
                } else {
                    values.add((String) value);
                }
            }
        }
        return values.toArray(new String[values.size()]);
    }

    @Override
    public void loadUsers() {
    }
}
