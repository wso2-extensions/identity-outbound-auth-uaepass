package org.wso2.carbon.identity.uaepass.authenticator.exception;

public class UAEPassUserInfoFailedException extends Exception{
    public UAEPassUserInfoFailedException(String message){
        super(message);
    }

    public UAEPassUserInfoFailedException(String message, Throwable cause){
        super(message,cause);
    }
}
