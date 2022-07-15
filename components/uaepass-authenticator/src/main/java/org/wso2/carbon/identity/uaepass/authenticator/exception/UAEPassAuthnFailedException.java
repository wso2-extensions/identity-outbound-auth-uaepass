package org.wso2.carbon.identity.uaepass.authenticator.exception;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

public class UAEPassAuthnFailedException extends AuthenticationFailedException {

    public UAEPassAuthnFailedException(String message){
        super(message);
    }

    public UAEPassAuthnFailedException(String message, String e){
        super(message,e);
    }

    public UAEPassAuthnFailedException(String message, Throwable cause){
        super(message,cause);
    }
}
