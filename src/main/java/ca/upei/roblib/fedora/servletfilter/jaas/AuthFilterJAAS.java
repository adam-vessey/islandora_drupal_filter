package ca.upei.roblib.fedora.servletfilter.jaas;

import java.io.IOException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import org.fcrepo.server.security.jaas.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthFilterJAAS extends UpstreamAuthFilterJAAS {
    protected static final Logger logger = LoggerFactory.getLogger(AuthFilterJAAS.class);

    /**
     * Performs the authentication. Once a Subject is obtained, it is stored in
     * the users session. Subsequent requests check for the existence of this
     * object before performing the authentication again.
     *
     * @param req
     *            the servlet request.
     * @return a user principal that was extracted from the login context.
     */
    @Override
    protected Subject authenticate(HttpServletRequest req) {
        String authorization = req.getHeader("authorization");
        if (authorization == null || authorization.trim().isEmpty()) {
            return null;
        }

        String user_agent = req.getHeader("User-Agent");
        if (user_agent == null || user_agent.trim().isEmpty()) {
            return null;
        }
        else {
            user_agent = user_agent.trim();
        }

        String token = String.format("%s/%s", user_agent, authorization);

        String auth = null;
        try {
            byte[] data = Base64.decode(authorization.substring(6));
            auth = new String(data);
        }
        catch (IOException e) {
            logger.error(e.toString());
            return null;
        }

        String username = auth.substring(0, auth.indexOf(':'));
        String password = auth.substring(auth.indexOf(':') + 1);

        // subject from session instead of re-authenticating
        // can't change username/password for this session.
        Subject subject = (Subject) req.getSession().getAttribute(token);
        if (subject != null) {
            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Got %s's subject from session for %s.", username, user_agent));
            }
            return subject;
        }
        else if (logger.isDebugEnabled()) {
            logger.debug(String.format("Authenticating %s against %s.", username, user_agent));
        }

        LoginContext loginContext = null;
        try {
            CallbackHandler handler = new CallbackHandlerImpl(username, password, user_agent);
            loginContext = new LoginContext(jaasConfigName, handler);
            loginContext.login();
        }
        catch (LoginException le) {
            logger.error(le.toString());
            return null;
        }

        // successfully logged in
        subject = loginContext.getSubject();

        // object accessible only by base64 encoded user_agent/username:password
        // that was
        // initially used - prevents some dodgy stuff
        req.getSession().setAttribute(token, subject);

        return subject;
    }

    protected static class CallbackHandlerImpl implements CallbackHandler {
        protected String username;
        protected String password;
        protected String userAgent;

        public CallbackHandlerImpl(String username, String password, String agent) {
            this.username = username;
            this.password = password;
            this.userAgent = agent;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback c: callbacks) {
                if (c instanceof NameCallback) {
                    ((NameCallback) c).setName(username);
                } else if (c instanceof PasswordCallback) {
                    ((PasswordCallback) c).setPassword(password.toCharArray());
                }
                else if (c instanceof KeyChoiceCallback) {
                    KeyChoiceCallback kcc = (KeyChoiceCallback)c;
                    kcc.setSelectedIndex(kcc.lookupKey(userAgent));
                }
                else {
                    throw new UnsupportedCallbackException(c);
                }
            }
        }
    }
}
