package ca.upei.roblib.fedora.servletfilter.jaas;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class MissingCredsException extends UnsupportedCallbackException {

    public MissingCredsException(Callback callback) {
        super(callback);
        // TODO Auto-generated constructor stub
    }

}
