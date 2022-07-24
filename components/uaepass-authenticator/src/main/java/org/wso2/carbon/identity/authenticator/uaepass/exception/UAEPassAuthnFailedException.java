/*
 *  Copyright (c) 2022, WSO2 LLC (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 LLC licenses this file to you under the Apache license,
 *  Version 2.0 (the "license"); you may not use this file except
 *  in compliance with the license.
 *  You may obtain a copy of the license at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.uaepass.exception;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

/**
 * An exception class which is used to send a UAEPass specific error code and error message when authenticator unable
 * to proceed the authentication.
 */
public class UAEPassAuthnFailedException extends AuthenticationFailedException {

    /**
     * An overloaded constructor which is used to throw an error code,error message and throwable cause once
     * authenticator unable to proceed the authentication with UAEPas.
     *
     * @param code      An error code specified to the authenticator.
     * @param message   An error message specified to the authenticator.
     * @param cause     The throwable cause which is supposed to pass to the caller method.
     */
    public UAEPassAuthnFailedException(String code, String message, Throwable cause) {

        super(code, message, cause);
    }
}
