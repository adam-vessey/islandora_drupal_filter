package ca.upei.roblib.fedora.servletfilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import junit.framework.TestCase;

public class DrupalAuthModuleTest extends TestCase {
    protected DrupalAuthModuleMock mockInstance;

    @Override
    @SuppressWarnings({
        "unchecked", "rawtypes"
    })
    public void setUp() throws Exception {
        super.setUp();

        mockInstance = new DrupalAuthModuleMock();
        mockInstance.initialize(new Subject(), new MockHandler(), new HashMap(), new HashMap());
    }

    public void testFindUserUserOneHasAdministratorRole() {
        mockInstance.findUser("alpha", "first");
        assertTrue("User \"1\" gets the \"administrator\" role",
                mockInstance.attributeValues.contains("administrator"));
    }

    public void testFindUserAnonymous() {
        mockInstance.findUser("anonymous", "anonymous");
        assertTrue("Anonymous gets the anonymous role",
                mockInstance.attributeValues.contains(DrupalAuthModule.ANONYMOUSROLE));
    }

    @SuppressWarnings({
        "rawtypes", "unchecked"
    })
    public void testFindUserAuthenticatedUser() {
        Map<String, String> users = new HashMap<String, String>();
        users.put("alpha", "first");
        users.put("bravo", "second");
        users.put("charlie", "third");

        for (String key : users.keySet()) {
            mockInstance = new DrupalAuthModuleMock();
            mockInstance.initialize(new Subject(), new MockHandler(), new HashMap(), new HashMap());
            mockInstance.findUser(key, users.get(key));
            mockInstance.attributeValues.contains("authenticated user");
        }
    }

    public void testFindUserAlphaConfiguredRoles() {
        mockInstance.findUser("alpha", "first");
        assertTrue("Alpha has proper roles",
                (mockInstance.attributeValues.contains("first role")
                        && mockInstance.attributeValues.contains("second role")
                        && mockInstance.attributeValues.contains("third role")));
    }

    public void testFindUserBravoConfiguredRoles() {
        mockInstance.findUser("bravo", "second");
        assertTrue("Bravo has proper roles",
                (!mockInstance.attributeValues.contains("first role")
                        && mockInstance.attributeValues.contains("second role")
                        && !mockInstance.attributeValues.contains("third role")));
    }

    public void testFindUserCharlieConfiguredRoles() {
        mockInstance.findUser("charlie", "third");
        assertTrue("Charlie has proper roles",
                (mockInstance.attributeValues.contains("authenticated user")
                        && !mockInstance.attributeValues.contains("first role")
                        && !mockInstance.attributeValues.contains("second role")
                        && !mockInstance.attributeValues.contains("third role")));
    }

    private class MockHandler implements CallbackHandler {
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            // No-op
        }
    }
}
