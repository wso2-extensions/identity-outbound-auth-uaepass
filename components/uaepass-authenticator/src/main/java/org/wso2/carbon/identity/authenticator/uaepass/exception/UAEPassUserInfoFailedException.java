/*
 *  Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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

/**
 * An exception class which is used to send a UAEPass specific error code and error message when authenticator unable
 * to proceed the user info request / user nfo data.
 */
public class UAEPassUserInfoFailedException extends Exception {

    /**
     * An overloaded constructor which is used to throw an error message and throwable cause once the authenticator
     * unable to proceed the user info request / user info data with UAEPas.
     *
     * @param message An error code specified to the authenticator.
     * @param cause   The throwable cause which is supposed to pass to the caller method.
     */
    public UAEPassUserInfoFailedException(String message, Throwable cause) {

        super(message, cause);
    }

}
