package ca.upei.roblib.fedora.servletfilter;

import java.io.InputStream;

public class DrupalAuthModuleMock extends DrupalAuthModule {
    protected InputStream stream;

    protected InputStream getConfig() {
        return this.stream;
    }

    @Override
    protected void findUser(String userid, String password) {
        stream = this.getClass().getResourceAsStream("/filter-drupal.xml");
        super.findUser(userid, password);
    }
}
