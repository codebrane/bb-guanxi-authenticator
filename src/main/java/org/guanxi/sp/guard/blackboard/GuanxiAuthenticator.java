//: "The contents of this file are subject to the Mozilla Public License
//: Version 1.1 (the "License"); you may not use this file except in
//: compliance with the License. You may obtain a copy of the License at
//: http://www.mozilla.org/MPL/
//:
//: Software distributed under the License is distributed on an "AS IS"
//: basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//: License for the specific language governing rights and limitations
//: under the License.
//:
//: The Original Code is Guanxi (http://www.guanxi.uhi.ac.uk).
//:
//: The Initial Developer of the Original Code is Alistair Young alistair@codebrane.com
//: All Rights Reserved.
//:

package org.guanxi.sp.guard.blackboard;

import blackboard.admin.persist.user.PersonLoader;
import blackboard.persist.BbPersistenceManager;
import blackboard.persist.KeyNotFoundException;
import blackboard.persist.PersistenceException;
import blackboard.platform.BbServiceManager;
import blackboard.platform.config.ConfigurationService;
import blackboard.platform.security.authentication.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;

/**
 * Custom Blackboard authenticator that works with a Guanxi Guard
 *
 * @author alistair
 */
public class GuanxiAuthenticator extends LDAPAuthModule {
  /** The name of the attribute that holds the uid of the user */
  private static final String PROPERTY_KEY_UID_ATTRIBUTE = "uid_attribute";
  /** Whether to automatically create users if they don't exist */
  private static final String PROPERTY_KEY_CREATE_USER = "create_user";
  /** The name of the request header that stores the name of the Guanxi Guard cookie */
  private static final String PROPERTY_KEY_GUANXI_GUARD_COOKIE_NAME_HEADER = "guanxi_guard_cookie_name_header";
  /**
   * The prefix the Guard puts in front of attributes in the request headers.
   * This has to be the same as:
   * webapps/login/WEB-INF/guanxi_sp_guard/config/guanxi-sp-guard.xml : AttributePrefix
   */
  private static final String PROPERTY_KEY_GUANXI_ATTRIBUTE_PREFIX = "guanxi_guard_attribute_prefix";
  /** The context path of the error page to use if something goes wrong */
  private static final String PROPERTY_KEY_ERROR_PAGE = "error_page";
  /** The delimiter the Guard uses to separate multiple values for an attribute */
  private static final String ATTRIBUTE_MULTI_VALUE_DELIMITER = ";";

  /** Logging definitions */
  private static final String LOG_MESSAGE_PREFIX = "GX:";
  private static final int INFO = -1;
  private static final int WARN = -2;
  private static final int ERROR = -3;

  // Instance variable populated by our config in config/authentication.properties
  private String uidAttributeName = null;
  private boolean createUser = false;
  private String guanxiGuardCookieNameHeader = null;
  private String attributePrefix = null;
  private String errorPage = null;

  public GuanxiAuthenticator() {
    super();
  }

  /**
   * The list of config options we support. These should be declared in
   * config/authentication.properties
   */
  private static String[] SHIB_PROP_KEYS = new String[] {
    PROPERTY_KEY_UID_ATTRIBUTE,
    PROPERTY_KEY_CREATE_USER,
    PROPERTY_KEY_GUANXI_GUARD_COOKIE_NAME_HEADER,
    PROPERTY_KEY_GUANXI_ATTRIBUTE_PREFIX,
    PROPERTY_KEY_ERROR_PAGE
  };

  /** @see blackboard.platform.security.authentication.BaseAuthenticationModule#getPropKeys() */
  public String[] getPropKeys() {
    String[] basePropKeys = super.getPropKeys();
    String[] combinedPropKeys = new String[(basePropKeys.length + SHIB_PROP_KEYS.length)];
    System.arraycopy(basePropKeys, 0, combinedPropKeys, 0, basePropKeys.length);
    System.arraycopy(SHIB_PROP_KEYS, 0, combinedPropKeys, basePropKeys.length, SHIB_PROP_KEYS.length);
    return combinedPropKeys;
  }

  /** @see blackboard.platform.security.authentication.BaseAuthenticationModule#setConfig(blackboard.platform.security.authentication.HttpAuthConfig) */
  public void setConfig(HttpAuthConfig config) {
    super.setConfig(config);
  }

  /** @see blackboard.platform.security.authentication.BaseAuthenticationModule#init(blackboard.platform.config.ConfigurationService) */
  public void init(ConfigurationService cfg) {
    super.init(cfg);

    // Load up all our config options from config/authentication.properties
    if (_config.getProperty(PROPERTY_KEY_CREATE_USER).toString().equalsIgnoreCase("true")) {
      createUser = true;
    }
    uidAttributeName = (String)_config.getProperty(PROPERTY_KEY_UID_ATTRIBUTE);
    attributePrefix = (String)_config.getProperty(PROPERTY_KEY_GUANXI_ATTRIBUTE_PREFIX);
    guanxiGuardCookieNameHeader = (String)_config.getProperty(PROPERTY_KEY_GUANXI_GUARD_COOKIE_NAME_HEADER);
    errorPage = (String)_config.getProperty(PROPERTY_KEY_ERROR_PAGE);
  }

  /** @see blackboard.platform.security.authentication.BaseAuthenticationModule#doAuthenticate(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse) */
  public String doAuthenticate(HttpServletRequest request,
                               HttpServletResponse response) throws BbSecurityException, BbAuthenticationFailedException,
                                                                    BbCredentialsNotFoundException {
    String userID = null;
    Enumeration headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String name = (String)headerNames.nextElement();
      String value = request.getHeader(name);
      if (name.startsWith(attributePrefix)) {
        if (name.equals(attributePrefix + uidAttributeName)) {
          // If it's a multi-valued attribute, take the first value
          if (value.contains(ATTRIBUTE_MULTI_VALUE_DELIMITER)) {
            userID = value.split(ATTRIBUTE_MULTI_VALUE_DELIMITER)[0];
          }
          else {
            userID = value;
          }
        }
      }
    }

    if (userID == null) {
      return super.doAuthenticate(request, response);
    }
    else if (!userExists(userID)) {
      throw new BbCredentialsNotFoundException("User " + userID + " does not exist");
    }
    else {
      return userID;
    }
  }

  protected String authenticate(String username, String password, SessionStub sessionStub, boolean useChallenge)
          throws BbAuthenticationFailedException, BbSecurityException {
    return super.authenticate(username, password, sessionStub, useChallenge);
  }

  /** @see blackboard.platform.security.authentication.BaseAuthenticationModule#doLogout(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse) */
  public void doLogout(HttpServletRequest request,
                       HttpServletResponse response) throws BbSecurityException {
    // Logout of the SSO session first
    doGuardLogout(request, guanxiGuardCookieNameHeader);
    super.doLogout(request, response);
  }

  /** @see blackboard.platform.security.authentication.BaseAuthenticationModule#getAuthType() */
  public String getAuthType() {
    return "ldap";
  }

  /**
   * Determines whether a uid exists in the system
   *
   * @param userID the uid of the user
   * @return true if the user exists, otherwise false
   */
  private boolean userExists(String userID) {
    BbPersistenceManager bbPersistenceManager = BbServiceManager.getPersistenceService().getDbPersistenceManager();
    
    PersonLoader personLoader;
    try {
      personLoader = (PersonLoader)bbPersistenceManager.getLoader(PersonLoader.TYPE);
    }
    catch (Exception e) {
      return false;
    }

    // Try to load person
    try {
      personLoader.load(userID);
      return true;
    }
    catch (KeyNotFoundException knfe) {
      // Person doesn't exist
      return false;
    }
    catch (PersistenceException e) {
      return false;
    }
  }

  /**
   * Redirects to the Guard error page and invalidates the current SSO session
   *
   * @param request the request
   * @param response the response
   * @param message the message to log
   */
  private void errorAndLogout(HttpServletRequest request, HttpServletResponse response, String message) {
    try {
      log(ERROR, message);
      doGuardLogout(request, guanxiGuardCookieNameHeader);
      request.setAttribute("gxMessage", message + " Please close the browser before trying again.");
      request.getRequestDispatcher(errorPage).forward(request, response);
    }
    catch(Exception e) {
      log(ERROR, e.getMessage());
    }
  }

  /**
   * Invalidates a Guanxi SSO session by getting rid of the Pod of attributes
   *
   * @param request the request
   * @param cookieNameHeader the name of the request header that stores the Guanxi Guard cookie name
   */
  private void doGuardLogout(HttpServletRequest request, String cookieNameHeader) {
    // Get the name of the cookie that points to the Pod of attributes
    String guanxiGuardCookieName = request.getHeader(cookieNameHeader);
    
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      for (int c = 0; c < cookies.length; c++) {
        if (cookies[c].getName().equals(guanxiGuardCookieName)) {
          // The cookie value points to the Pod of attributes
          request.getSession().getServletContext().setAttribute(cookies[c].getValue(), null);
        }
      }
    }
  }

  /**
   * Logs to logs/bb-services-log.txt
   *
   * @param level the log level
   * @param message the log message
   */
  private void log(int level, String message) {
    switch(level) {
      case INFO:
        _logger.logInfo(LOG_MESSAGE_PREFIX + message);
        break;
      case WARN:
        _logger.logWarning(LOG_MESSAGE_PREFIX + message);
        break;
      case ERROR:
        _logger.logError(LOG_MESSAGE_PREFIX + message);
        break;
    }
  }
}
