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

package org.wso2.carbon.identity.authenticator.uaepass;

/**
 * Includes all the constants variables used by the UAEPass authenticator.
 */
public class UAEPassAuthenticatorConstants {

    public enum ErrorMessages {

        USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP("UAEPass-65001",
                "Cannot find the userId from the id_token sent by the UAEPass IDP."),
        RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED("UAEPass-65002",
                "Error while retrieving multi attribute separator"),
        AUTHENTICATION_FAILED_PROCESSING_ADDITIONAL_QUERY_PARAMS("UAEPass-65003",
                "Authentication process failed. Unable to process additional query parameters."),
        AUTHENTICATION_FAILED_ENV_SELECTION("UAEPass-65004", "Unable to pick correct env or a problem" +
                "occurred in additional query params when generating the authorize request."),
        AUTHENTICATION_FAILED_COMPULSORY_QUERY_PARAM_FAILURE("UAEPass-65005",
                "Authentication process failed. Unable to build the request with compulsory query parameters."),
        AUTHENTICATION_FAILED_RETRIEVING_OAUTH_CLIENT_RESPONSE("UAEPass-65006", "Authentication process "
                + "failed. Unable to get OAuth client response."),
        AUTHENTICATION_FAILED_ACCESS_TOKEN_REQUEST_FAILURE("UAEPass-65007", "Authentication process " +
                "failed. Unable to build the access token request."),
        AUTHENTICATION_FAILED_AUTHORIZED_RESPONSE_FAILURE("UAEPass-65008", "Authentication process " +
                "failed. Unable to get the OAuth authorization response."),
        UAEPASS_AUTHN_FAILED_EXCEPTION("UAEPass-65009", "Unable to return OAuth client response"),
        UAEPASS_AUTHEN_FAILED_PROCESSING_ADDITIONAL_QUERY_PARAMS("UAEPass-65010",
                "UAEPaas Authentication process failed. Unable to set additional query parameters to the " +
                        "authorize request"),
        UAEPASS_AUTHN_FAILED_ACCESS_TOKEN_BUILD_FAILURE("UAEPass-65011", "UAEPass Authentication" +
                "Exception while building access token request with the request body"),
        UAEPASS_AUTHN_FAILED_ABSOLUTE_URL_BUILD_FAILURE("UAEPass-65012", "Error occurred while " +
                "extracting the absolute public URL from the browser");

        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s  - %s", code, message);
        }
    }

    public static class UAEPassRuntimeConstants {

        public static final String SUB = "sub";
        public static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
        public static final String DEFAULT_ACR_VALUES = "urn:safelayer:tws:policies:authentication:level:low";
        public static final String DEFAULT_SCOPES = "urn:uae:digitalid:profile:general";
        public static final String[] NON_USER_ATTRIBUTES = new String[]{"at_hash", "iss", "iat", "exp", "aud", "azp"};
        public static final String PRODUCTION = "Production";
        public static final String STAGING = "Staging";
        public static final String SANDBOX_STAGE_CLIENT_ID = "sandbox_stage";
    }

    public class Endpoints {

        public class StagingEndpointKeys {

            public static final String UAEPASS_STG_AUTHZ_ENDPOINT_KEY = "UAEPassSTGAuthzEndpoint";
            public static final String UAEPASS_STG_TOKEN_ENDPOINT_KEY = "UAEPassSTGTokenEndpoint";
            public static final String UAEPASS_STG_USER_INFO_ENDPOINT_KEY = "UAEPassSTGUserInfoEndpoint";
            public static final String UAEPASS_STG_LOGOUT_ENDPOINT_KEY = "UAEPassSTGLogoutEndpoint";
        }

        public class ProductionEndpointKeys {

            public static final String UAEPASS_PROD_AUTHZ_ENDPOINT_KEY = "UAEPassPRODAuthzEndpoint";
            public static final String UAEPASS_PROD_TOKEN_ENDPOINT_KEY = "UAEPassPRODTokenEndpoint";
            public static final String UAEPASS_PROD_USER_INFO_ENDPOINT_KEY = "UAEPassPRODUserInfoEndpoint";
            public static final String UAEPASS_PROD_LOGOUT_ENDPOINT_KEY = "UAEPassPRODLogoutEndpoint";
        }

        public class StagingEndpointValues {

            public static final String UAEPASS_STG_AUTHZ_ENDPOINT_VALUE = "https://stg-id.uaepass.ae/idshub/authorize";
            public static final String UAEPASS_STG_TOKEN_ENDPOINT_VALUE = "https://stg-id.uaepass.ae/idshub/token";
            public static final String UAEPASS_STG_USER_INFO_ENDPOINT_VALUE =
                    "https://stg-id.uaepass.ae/idshub/userinfo";
            public static final String UAEPASS_STG_LOGOUT_ENDPOINT_VALUE = "https://stg-id.uaepass.ae/idshub/logout";
        }

        public class ProductionEndpointValues {

            public static final String UAEPASS_PROD_AUTHZ_ENDPOINT_VALUE = "https://id.uaepass.ae/idshub/authorize";
            public static final String UAEPASS_PROD_TOKEN_ENDPOINT_VALUE = "https://id.uaepass.ae/idshub/token";
            public static final String UAEPASS_PROD_USER_INFO_ENDPOINT_VALUE = "https://id.uaepass.ae/idshub/userinfo";
            public static final String UAEPASS_PROD_LOGOUT_ENDPOINT_VALUE = "https://id.uaepass.ae/idshub/logout";
        }
    }

    public class UAE {

        public static final String FEDERATED_IDP_COMPONENT_NAME = "UAEPassAuthenticator";
        public static final String FEDERATED_IDP_COMPONENT_FRIENDLY_NAME = "UAEPass";
        public static final String LOGIN_TYPE = "OIDC";
        public static final String ACCESS_TOKEN = "access_token";
        public static final String ID_TOKEN = "id_token";
        public static final String CLIENT_ID = "client_id";
        public static final String CLIENT_SECRET = "ClientSecret";
        public static final String CALLBACK_URL = "callbackUrl";
        public static final String ACR_VALUES = "acr_values";
        public static final String REDIRECT_URI = "redirect_uri";
        public static final String SCOPE = "scope";
        public static final String OAUTH2_GRANT_TYPE_CODE = "code";
        public static final String OAUTH2_PARAM_STATE = "state";
        public static final String QUERY_PARAMS = "commonAuthQueryParams";
        public static final String UAEPASS_ENV = "IsStagingEnv";
        public static final String HTTP_ORIGIN_HEADER = "Origin";
        public static final String LOGOUT_ENABLE = "IsLogoutEnable";
    }

    public class UAEPassPropertyConstants {

        public static final String TEXTBOX = "string";
        public static final String CHECKBOX = "boolean";
    }
}
