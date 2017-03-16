package ca.upei.roblib.fedora.servletfilter;

import java.io.IOException;
import java.util.List;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;

public class DrupalMultisiteAuthModuleMock extends DrupalMultisiteAuthModule {
    protected String key;

    public DrupalMultisiteAuthModuleMock(String key) throws IOException, DocumentException {
        super();
        this.key = key;
    }

    @Override
    protected void parseConfig() throws DocumentException, IOException {
        Document doc = getParsedConfig(this.getClass().getResourceAsStream("/filter-drupal-multisite.xml"));

        @SuppressWarnings("unchecked")
        List<Element> list = doc.selectNodes("//FilterDrupal_Connection/connection");
        for (Element el : list) {
            config.put(key, parseConnectionElement(el));
            // One is all we need.
            break;
        }
    }
}
