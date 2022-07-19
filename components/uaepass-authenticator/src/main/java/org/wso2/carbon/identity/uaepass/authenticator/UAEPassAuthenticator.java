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

package org.wso2.carbon.identity.uaepass.authenticator;

import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONArray;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.uaepass.authenticator.exception.UAEPassAuthnFailedException;
import org.wso2.carbon.identity.uaepass.authenticator.exception.UAEPassUserInfoFailedException;
import org.wso2.carbon.identity.uaepass.authenticator.internal.UAEPassDataHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The UAEPassAuthenticator class contains all the functional tasks handled by the authenticator with UAEPass IdP and
 * WSO2 Identity Server, such as obtaining an authorization code and access token, federated logout with
 * commonauthLogout of the UAEPAss, claim mapping via both id token and user info, UAEPAss Environment
 * selection (Staging / Production), and obtaining user input data.
 */
public class UAEPassAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(UAEPassAuthenticator.class);

    /**
     * Checks whether the request and response can handle by the authenticator.
     *
     * @param request   The request that is received by the authenticator.
     * @return Boolean  Whether the request can be handled by the authenticator.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        return UAEPassAuthenticatorConstants.UAE.LOGIN_TYPE.equals(getLoginType(request));
    }

    /**
     * Returns the federated IdP component's friendly name.
     *
     * @return String   The display name of the authenticator.
     */
    @Override
    public String getFriendlyName() {

        return UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_FRIENDLY_NAME;
    }

    /**
     * Returns the federated IdP component name.
     *
     * @return String   The identifier of the authenticator
     */
    @Override
    public String getName() {

        return UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_NAME;
    }

    /**
     * Returns the claim dialect URL.
     * Since authenticator supports OIDC, the dialect URL is OIDC dialect.
     *
     * @return String  The dialect which supposed to map UAEPass claims
     */
    @Override
    public String getClaimDialectURI() {

        return UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.OIDC_DIALECT;
    }

    /**
     * Returns a unique string to identify each request and response separately.
     * This contains the session id, processed by the WSO2 IS.
     *
     * @param request  The request that is received by the authenticator.
     * @return String  Returns the state parameter value that is carried bt the request.
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String state = request.getParameter(UAEPassAuthenticatorConstants.UAE.OAUTH2_PARAM_STATE);
        if (StringUtils.isNotBlank(state)) {
            return state.split(",")[0];
        } else {
            LOG.error("An unique identifier cannot be issue for both Request and Response. ContextIdentifier is NULL.");
            return null;
        }
    }

    /**
     * Returns the all user input fields of the authenticator.
     *
     * @return List<Property>  Returns the federated authenticator properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(UAEPassAuthenticatorConstants.UAE.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter OAuth2/OpenID Connect client identifier value.");
        clientId.setType(UAEPassAuthenticatorConstants.UAEPassPropertyConstants.TEXTBOX);
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(UAEPassAuthenticatorConstants.UAE.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setDescription("Enter OAuth2/OpenID Connect client secret value.");
        clientSecret.setType(UAEPassAuthenticatorConstants.UAEPassPropertyConstants.TEXTBOX);
        clientSecret.setDisplayOrder(2);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setRequired(true);
        callbackUrl.setName(UAEPassAuthenticatorConstants.UAE.CALLBACK_URL);
        callbackUrl.setDescription("The callback URL used to partner identity provider credentials.");
        callbackUrl.setType(UAEPassAuthenticatorConstants.UAEPassPropertyConstants.TEXTBOX);
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property additionalQueryParams = new Property();
        additionalQueryParams.setName(UAEPassAuthenticatorConstants.UAE.QUERY_PARAMS);
        additionalQueryParams.setDisplayName("Additional Query Parameters");
        additionalQueryParams.setRequired(false);
        additionalQueryParams.setDescription("Add the additional query parameters.");
        additionalQueryParams.setType(UAEPassAuthenticatorConstants.UAEPassPropertyConstants.TEXTBOX);
        additionalQueryParams.setDisplayOrder(4);
        configProperties.add(additionalQueryParams);

        Property logoutEnabled = new Property();
        logoutEnabled.setName(UAEPassAuthenticatorConstants.UAE.LOGOUT_ENABLE);
        logoutEnabled.setDisplayName("If Logout is Enabled");
        logoutEnabled.setRequired(false);
        logoutEnabled.setDescription("Check here to enable the logout.");
        logoutEnabled.setType(UAEPassAuthenticatorConstants.UAEPassPropertyConstants.CHECKBOX);
        logoutEnabled.setDisplayOrder(5);
        configProperties.add(logoutEnabled);

        Property isStagingEnv = new Property();
        isStagingEnv.setName(UAEPassAuthenticatorConstants.UAE.UAEPASS_ENV);
        isStagingEnv.setDisplayName("If Staging Environment");
        isStagingEnv.setRequired(false);
        isStagingEnv.setDescription("Check here, if using the Staging environment.");
        isStagingEnv.setType(UAEPassAuthenticatorConstants.UAEPassPropertyConstants.CHECKBOX);
        isStagingEnv.setDisplayOrder(6);
        configProperties.add(isStagingEnv);

        return configProperties;
    }

    /**
     * Redirects the user to the login page for authentication purposes. This authenticator redirects the user to the
     * application's login page, which is set up on the UAE Pass side, which works as the external Identity Provider.
     *
     * @param request                          The request that is received by the authenticator.
     * @param response                         Appends the authorized URL once a valid authorized URL built.
     * @param context                          The Authentication context received by authenticator.
     * @throws AuthenticationFailedException   Exception while creating the authorization code
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authentication request has initialized.");
            }
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String envUAEPass = getUAEPassEnvironment(context);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("UAEPass " + envUAEPass + " environment selected.");
                }
                String clientId = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CLIENT_ID);
                String authorizationEP = getAuthorizeUrl(envUAEPass);
                String callBackUrl = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CALLBACK_URL);
                String state = context.getContextIdentifier() + "," + UAEPassAuthenticatorConstants.UAE.LOGIN_TYPE;

                OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).
                        setClientId(clientId).setRedirectURI(callBackUrl).
                        setResponseType(UAEPassAuthenticatorConstants.UAE.OAUTH2_GRANT_TYPE_CODE).setState(state).
                        buildQueryMessage();

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authorization request contains the compulsory query parameters.");
                }
                String loginPage = authzRequest.getLocationUri();

                if (StringUtils.isNotBlank(authenticatorProperties.get(UAEPassAuthenticatorConstants.
                        UAE.QUERY_PARAMS))) {
                    loginPage = processAdditionalQueryParamSeperation(authenticatorProperties, loginPage);
                } else {
                    Map<String, String> paramMap = new HashMap<>();
                    paramMap.put(UAEPassAuthenticatorConstants.UAE.ACR_VALUES,
                            UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.DEFAULT_ACR_VALUES);
                    paramMap.put(UAEPassAuthenticatorConstants.UAE.SCOPE,
                            UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.DEFAULT_SCOPES);
                    loginPage = FrameworkUtils.buildURLWithQueryParams(loginPage, paramMap);
                }

                response.sendRedirect(loginPage);
            } else {
                throw new AuthenticationFailedException("Error while retrieving properties. "
                        + "Authenticator properties cannot be null.");
            }

        } catch (UAEPassAuthnFailedException e) {
            throw new AuthenticationFailedException("Authentication process failed." +
                    "Unable to process additional query parameters.", e);
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Authorization request building failed.");
            }
            throw new AuthenticationFailedException("Unable to pick correct env or a problem occurred in additional "
                    + "query params when generating the authorize request.", e);
        } catch (OAuthSystemException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Unable to build the request with compulsory query parameters.");
            }
            throw new AuthenticationFailedException("Authentication process failed." +
                    "Unable to build the request with compulsory query parameters.", e);
        }
    }

    /**
     * Implements the logic of user authentication with the UAEPass.
     *
     * @param request                         The request that is received by the authenticator.
     * @param response                        The response that is received to the authenticator.
     * @param context                         The Authentication context received by authenticator.
     * @throws AuthenticationFailedException  Exception while creating the access token or id token
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOAuthResponse(oAuthClient, accessTokenRequest);

            String accessToken = oAuthResponse.getParam(UAEPassAuthenticatorConstants.UAE.ACCESS_TOKEN);
            if (StringUtils.isBlank(accessToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Access token is empty.");
                }
                throw new AuthenticationFailedException("Access token is empty.");
            }

            String idToken = oAuthResponse.getParam(UAEPassAuthenticatorConstants.UAE.ID_TOKEN);

            AuthenticatedUser authenticatedUser;
            Map<String, Object> jsonClaimMap;
            Map<ClaimMapping, String> claims = new HashMap<>();

            if (StringUtils.isNotBlank(idToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Id token available from UAEPass.");
                }
                context.setProperty(UAEPassAuthenticatorConstants.UAE.ACCESS_TOKEN, accessToken);
                jsonClaimMap = getIdTokenClaims(context, idToken);
            } else {
                jsonClaimMap = getUserInfoUserAttributes(oAuthResponse, context);
            }

            String authenticatedUserId = getAuthenticatedUserId(context, jsonClaimMap);
            String attributeSeparator = getMultiAttributeSeparator(context, authenticatedUserId);

            jsonClaimMap.entrySet().stream().filter(entry -> !ArrayUtils.contains(UAEPassAuthenticatorConstants.
                            UAEPassRuntimeConstants.NON_USER_ATTRIBUTES, entry.getKey())).
                    forEach(entry -> buildClaimMappings(claims, entry, attributeSeparator));

            if (StringUtils.isBlank(authenticatedUserId)) {
                throw new AuthenticationFailedException("Cannot find the userId from the id_token sent "
                        + "by the federated IDP.");
            }
            authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier
                    (authenticatedUserId);
            authenticatedUser.setUserAttributes(claims);
            context.setSubject(authenticatedUser);

        } catch (UAEPassAuthnFailedException e) {
            throw new AuthenticationFailedException("Authentication process failed. " +
                    "Unable to get OAuth client response.", e);
        } catch (UAEPassUserInfoFailedException e) {
            throw new AuthenticationFailedException("Authentication process failed." +
                    "Unable to build access token request.", e);
        } catch (OAuthProblemException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("OAuth authorize response failure.");
            }
            throw new AuthenticationFailedException("Authentication process failed.", e);
        }
    }

    /**
     * Logout initialization will be handled by this method. This includes the functionality to support
     * common-auth logout of the UAEPass.
     *
     * @param request                 The request that is received by the authenticator.
     * @param response                Appends the logout redirect URI once logged out from authenticator.
     * @param context                 The Authentication context received by authenticator.
     * @throws LogoutFailedException  LogoutFailedException will be thrown if unable to process the common-auth
     *                                logout from UAEPass.
     */
    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) throws LogoutFailedException {

        if (isLogoutEnabled(context)) {
            try {
                Map<String, String> paramMap = new HashMap<>();
                Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

                String logoutRedirectUri = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CALLBACK_URL);
                paramMap.put(UAEPassAuthenticatorConstants.UAE.REDIRECT_URI, logoutRedirectUri);
                String sessionID = context.getContextIdentifier() + "," + UAEPassAuthenticatorConstants.UAE.LOGIN_TYPE;
                paramMap.put(UAEPassAuthenticatorConstants.UAE.OAUTH2_PARAM_STATE, sessionID);

                String envUAEPass = getUAEPassEnvironment(context);
                String logoutUrl = getLogoutUrl(envUAEPass);
                logoutUrl = FrameworkUtils.buildURLWithQueryParams(logoutUrl, paramMap);
                logoutUrl = modifyLogoutUrl(logoutUrl);
                response.sendRedirect(logoutUrl);

            } catch (IOException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.error("Error in initiate logout URI build.", e);
                }
                String idpName = context.getExternalIdP().getName();
                String tenantDomain = context.getTenantDomain();
                throw new LogoutFailedException("Error occurred while initiating the logout request to IdP: " + idpName
                        + " of tenantDomain: " + tenantDomain, e);
            }
        } else {
            super.initiateLogoutRequest(request, response, context);
        }
    }

    /**
     * After successful logout, WSO2 IS returns this response.
     * Contains the details about the SP.
     *
     * @param request   The request that is received by the authenticator.
     * @param response  The response that is received to the authenticator.
     * @param context   The Authentication context received by authenticator.
     */
    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) {

        if (LOG.isDebugEnabled()) {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                LOG.debug("Handled logout response from service provider " + request.getParameter("sp") +
                        " in tenant domain " + IdentityTenantUtil.getTenantDomainFromContext());
            } else {
                LOG.debug("Handled logout response from service provider " + request.getParameter("sp") +
                        " in tenant domain " + request.getParameter("tenantDomain"));
            }
        }
    }

    /**
     * This method is used add additional parameters along with the authorize request.
     *
     * @param authenticatorProperties  The user input fields of the authenticator.
     * @param loginPage                Current authorize URL.
     * @return authzUrl                Returns the modified authorized URL appending the additional query params.
     */
    public String processAdditionalQueryParamSeperation(Map<String, String> authenticatorProperties, String loginPage)
        throws UAEPassAuthnFailedException {

        String additionalQueryParams = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.QUERY_PARAMS);
        String[] splittedQueryParamsArr;

        if (additionalQueryParams.contains(",")) {
            splittedQueryParamsArr = additionalQueryParams.split(",");
        } else {
            splittedQueryParamsArr = additionalQueryParams.split("&");
        }

        String[] keyValuePairs;
        Map<String, String> paramMap = new HashMap<>();

        for (int i = 0; i < splittedQueryParamsArr.length; i++) {
            keyValuePairs = (splittedQueryParamsArr[i]).split("=");
            paramMap.put(keyValuePairs[0], keyValuePairs[1]);
        }
        String finalAuthzUrl = null;
        try {
            String authzUrl = FrameworkUtils.buildURLWithQueryParams(loginPage, paramMap);
            if (!(authzUrl.contains(UAEPassAuthenticatorConstants.UAE.ACR_VALUES))) {
                paramMap.put(UAEPassAuthenticatorConstants.UAE.ACR_VALUES,
                        UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.DEFAULT_ACR_VALUES);
            }
            if (!(authzUrl.contains(UAEPassAuthenticatorConstants.UAE.SCOPE))) {
                paramMap.put(UAEPassAuthenticatorConstants.UAE.SCOPE,
                        UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.DEFAULT_SCOPES);
            }
            finalAuthzUrl = FrameworkUtils.buildURLWithQueryParams(loginPage, paramMap);
        } catch (IllegalArgumentException | UnsupportedEncodingException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Authorize URL creation failed with the additional query parameters issue.");
            }
            throw new UAEPassAuthnFailedException("Authentication process failed. Unable to set " +
                    "additional query parameters to the authorize request.", e);
        }

        return finalAuthzUrl;
    }

    /**
     * This method is used to retrieve user claims as key value pairs to the Java Map object from user info endpoint.
     *
     * @param oAuthResponse         The response from OAuthClient to authenticator by the UAEPass.
     *                              (Use to teh get access token)
     * @param context               The Authentication context received by authenticator.
     * @return Map<String, Object>  Map object of key value pairs of the logged user.
     */
    public Map<String, Object> getUserInfoUserAttributes(OAuthClientResponse oAuthResponse,
                                                         AuthenticationContext context)
            throws UAEPassUserInfoFailedException {

        String accessToken = oAuthResponse.getParam(UAEPassAuthenticatorConstants.UAE.ACCESS_TOKEN);
        String userInfoJsonPayload;
        Map<String, Object> userInfoJwtAttributes = null;

        try {
            userInfoJsonPayload = sendUserInfoRequest(context, accessToken);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully returns the userinfo JSON payload");
            }
            Set<Map.Entry<String, Object>> jwtAttributeSet;
            jwtAttributeSet = JSONObjectUtils.parse(userInfoJsonPayload).entrySet();
            userInfoJwtAttributes = buildJSON(jwtAttributeSet);

        } catch (UAEPassUserInfoFailedException e) {
            throw new UAEPassUserInfoFailedException("Unable to retrieve claims from user info.", e);
        } catch (ParseException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Error occurred while parsing user info payload by UAEPass.");
            }
            throw new UAEPassUserInfoFailedException("Error occurred while parsing user info payload by UAEPass.", e);
        }

        return userInfoJwtAttributes;
    }

    /**
     * This method is used to create userinfo request with the access token.
     *
     * @param context                          The Authentication context received by authenticator.
     * @param accessToken                      The access token obtained from the processAuthenticationResponse.
     * @return String                          The response which returns from the user info API call.
     * @throws UAEPassUserInfoFailedException  Throws an exception, if not obtains the user claims from the user info.
     */
    public String sendUserInfoRequest(AuthenticationContext context, String accessToken)
            throws UAEPassUserInfoFailedException {

        StringBuilder builder = new StringBuilder();

        try {
            String envUAEPass = getUAEPassEnvironment(context);
            URL userInfoUrl = new URL(getUserInfoUrl(envUAEPass));
            HttpURLConnection httpURLConnection = (HttpURLConnection) userInfoUrl.openConnection();
            httpURLConnection.setRequestMethod("GET");
            httpURLConnection.setRequestProperty("Authorization", "Bearer " + accessToken);
            BufferedReader reader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
            String inputLine = reader.readLine();

            if (LOG.isDebugEnabled()) {
                LOG.debug("User info request is sent successfully.");
            }

            while (inputLine != null) {
                builder.append(inputLine).append("\n");
                inputLine = reader.readLine();
            }

        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Unable to retrieve successful response from UAEPass UserInfo", e);
            }
            throw new UAEPassUserInfoFailedException("UAEPass UserInfo failure.", e);
        }
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            LOG.debug("response: " + builder);
        }

        return builder.toString();
    }

    /**
     * Returns the user context of authenticated user.
     *
     * @param oidcClaims
     * @return String
     */
    public String getAuthenticatedUser(Map<String, Object> oidcClaims) {

        return (String) oidcClaims.get(UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.SUB);
    }

    /**
     * Returns the user id of the authenticated user.
     *
     * @param context                          The Authentication context received by authenticator.
     * @param userClaims                       The Map object with user claims returns from buildJSON.
     * @return String                          The ID of the authenticated user from UAEPass.
     * @throws AuthenticationFailedException
     */
    public String getAuthenticatedUserId(AuthenticationContext context, Map<String, Object> userClaims)
            throws AuthenticationFailedException {

        String authenticatedUserId;
        if (isUserIdFoundAmongClaims(context)) {
            authenticatedUserId = getSubjectFromUserIDClaimURI(context, userClaims);
            if (StringUtils.isNotBlank(authenticatedUserId)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authenticated user id: " + authenticatedUserId + " was found among id_token claims.");
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Subject claim could not be found amongst id_token claims. Defaulting to the 'sub' " +
                            "attribute in id_token as authenticated user id.");
                }
                authenticatedUserId = getAuthenticatedUser(userClaims);
            }
        } else {
            authenticatedUserId = getAuthenticatedUser(userClaims);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
            }
        }

        if (StringUtils.isBlank(authenticatedUserId)) {
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getCode(),
                    UAEPassAuthenticatorConstants.ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.
                            getMessage());
        }

        return authenticatedUserId;
    }

    /**
     * Checks whether the valid OIDC claim available in the OIDC claims in WSO2 Identity Server.
     *
     * @param context   The Authentication context received by authenticator.
     * @return Boolean
     */
    public boolean isUserIdFoundAmongClaims(AuthenticationContext context) {

        return Boolean.parseBoolean(context.getAuthenticatorProperties().get(IdentityApplicationConstants.
                Authenticator.OIDC.IS_USER_ID_IN_CLAIMS));
    }

    /**
     * @param context                           The Authentication context received by authenticator.
     * @param userClaims                        The Map object with user claims returns from buildJSON.
     * @return String
     * @throws AuthenticationFailedException
     */
    public String getSubjectFromUserIDClaimURI(AuthenticationContext context, Map<String, Object> userClaims)
            throws AuthenticationFailedException {

        boolean useLocalClaimDialect = context.getExternalIdP().useDefaultLocalIdpDialect();
        String userIdClaimUri = context.getExternalIdP().getUserIdClaimUri();
        String spTenantDomain = context.getTenantDomain();

        try {
            String userIdClaimUriInOIDCDialect = null;
            if (useLocalClaimDialect) {
                if (StringUtils.isNotBlank(userIdClaimUri)) {
                    userIdClaimUriInOIDCDialect = getUserIdClaimUriInOIDCDialect(userIdClaimUri, spTenantDomain);
                } else {
                    if (LOG.isDebugEnabled()) {
                        String idpName = context.getExternalIdP().getIdPName();
                        LOG.debug("User ID Claim URI is not configured for IDP: " + idpName + ". " +
                                "Cannot retrieve subject using user id claim URI.");
                    }
                }
            } else {
                ClaimMapping[] claimMappings = context.getExternalIdP().getClaimMappings();
                // Try to find the userIdClaimUri within the claimMappings.
                if (!ArrayUtils.isEmpty(claimMappings)) {
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Evaluating " + claimMapping.getRemoteClaim().getClaimUri() + " against "
                                    + userIdClaimUri);
                        }
                        if (StringUtils.equals(claimMapping.getRemoteClaim().getClaimUri(), userIdClaimUri)) {
                            // Get the subject claim in OIDC dialect.
                            String userIdClaimUriInLocalDialect = claimMapping.getLocalClaim().getClaimUri();
                            userIdClaimUriInOIDCDialect = getUserIdClaimUriInOIDCDialect(userIdClaimUriInLocalDialect,
                                    spTenantDomain);
                            break;
                        }
                    }
                }
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("using userIdClaimUriInOIDCDialect to get subject from idTokenClaims: "
                        + userIdClaimUriInOIDCDialect);
            }
            Object subject = userClaims.get(userIdClaimUriInOIDCDialect);
            if (subject instanceof String) {
                return (String) subject;
            } else if (subject != null) {
                LOG.warn("Unable to map subject claim (non-String type): " + subject);
            }
        } catch (ClaimMetadataException ex) {
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    EXECUTING_CLAIM_TRANSFORMATION_FOR_IDP_FAILED.getCode(),
                    String.format(UAEPassAuthenticatorConstants.ErrorMessages.
                                    EXECUTING_CLAIM_TRANSFORMATION_FOR_IDP_FAILED.getMessage(),
                            context.getExternalIdP().getIdPName()), ex);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Couldn't find the subject claim among id_token claims for IDP: " +
                    context.getExternalIdP().getIdPName());
        }
        return null;
    }

    /**
     * Returns the claim URIs from UAEPass.
     *
     * @param userIdClaimInLocalDialect
     * @param spTenantDomain             Tenant domain name, where the SP has configured.
     * @return String
     * @throws ClaimMetadataException
     */
    public String getUserIdClaimUriInOIDCDialect(String userIdClaimInLocalDialect, String spTenantDomain)
            throws ClaimMetadataException {

        List<ExternalClaim> externalClaims = UAEPassDataHolder.
                getInstance().
                getClaimMetadataManagementService().
                getExternalClaims(UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.OIDC_DIALECT, spTenantDomain);
        String userIdClaimUri = null;
        ExternalClaim oidcUserIdClaim = null;

        for (ExternalClaim externalClaim : externalClaims) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Evaluating " + userIdClaimInLocalDialect + " against " +
                        externalClaim.getMappedLocalClaim());
            }
            if (userIdClaimInLocalDialect.equals(externalClaim.getMappedLocalClaim())) {
                oidcUserIdClaim = externalClaim;
            }
        }
        if (oidcUserIdClaim != null) {
            userIdClaimUri = oidcUserIdClaim.getClaimURI();
        }

        return userIdClaimUri;
    }

    /**
     * Map the claim values according to the attribute separator.
     *
     * @param claims
     * @param entry
     * @param separator
     */
    public void buildClaimMappings(Map<ClaimMapping, String> claims, Map.Entry<String, Object> entry,
                                   String separator) {

        StringBuilder claimValue = null;
        if (StringUtils.isBlank(separator)) {
            separator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
        }
        if (entry.getValue() instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) entry.getValue();
            if (jsonArray != null && !jsonArray.isEmpty()) {
                Iterator<Object> attributeIterator = jsonArray.iterator();
                while (attributeIterator.hasNext()) {
                    if (claimValue == null) {
                        claimValue = new StringBuilder(attributeIterator.next().toString());
                    } else {
                        claimValue.append(separator).append(attributeIterator.next().toString());
                    }
                }
            }
        } else {
            claimValue = entry.getValue() != null ?
                    new StringBuilder(entry.getValue().toString()) : new StringBuilder();
        }
        claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                claimValue != null ? claimValue.toString() : StringUtils.EMPTY);
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            LOG.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : " + claimValue);
        }
    }

    /**
     * Separate the attribute from the received payload.
     *
     * @param context                         The Authentication context received by authenticator.
     * @param authenticatedUserId             The user id of authenticated user.
     * @return String                         The element which used to separate the attributes from the JSON payload.
     * @throws AuthenticationFailedException
     */
    public String getMultiAttributeSeparator(AuthenticationContext context, String authenticatedUserId)
            throws AuthenticationFailedException {

        String attributeSeparator = null;
        try {
            String tenantDomain = context.getTenantDomain();
            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            int tenantId = UAEPassDataHolder.getInstance().getRealmService().getTenantManager().
                    getTenantId(tenantDomain);
            UserRealm userRealm = UAEPassDataHolder.getInstance().getRealmService().getTenantUserRealm(tenantId);

            if (userRealm != null) {
                UserStoreManager userStore = (UserStoreManager) userRealm.getUserStoreManager();
                attributeSeparator = userStore.getRealmConfiguration().getUserStoreProperty(IdentityCoreConstants.
                        MULTI_ATTRIBUTE_SEPARATOR);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("For the claim mapping: " + attributeSeparator + " " +
                            "is used as the attributeSeparator in " + "tenant: " + tenantDomain);
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.
                    ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getCode(),
                    UAEPassAuthenticatorConstants.ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.
                            getMessage(), AuthenticatedUser.
                    createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId), e);
        }

        return attributeSeparator;
    }

    /**
     * This method is used to retrieve user claims from id token.
     *
     * @param context               The Authentication context received by authenticator.
     * @param idToken               The received Id token from the processAuthenticationResponse.
     * @return Map<Strng, Object>   Decoded JWT payload via JSON Key value pairs.
     */
    public Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(UAEPassAuthenticatorConstants.UAE.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parse(new String(decoded)).entrySet();
        } catch (ParseException e) {
            LOG.error("Error occurred while parsing JWT ID token provided by UAEPass.", e);
        }
        Map<String, Object> userInfoJwtAttributes = buildJSON(jwtAttributeSet);

        return userInfoJwtAttributes;
    }

    /**
     * Request the access token - Create a request to access token endpoint of the external IdP.
     *
     * @param context                       The Authentication context received by authenticator.
     * @param authzResponse                 The response from to authorize endpoint. (To get the received
     *                                      authorize code.)
     * @return OAuthClientRequest           Returns the access token call which built.
     * @throws UAEPassAuthnFailedException  Exception throws if unable to process the token request.
     */
    public OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse authzResponse)
            throws UAEPassAuthnFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        OAuthClientRequest accessTokenRequest = null;
        try {
            String envUAEPass = getUAEPassEnvironment(context);
            String clientId = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CLIENT_SECRET);
            String tokenEndPoint = getTokenUrl(envUAEPass);
            String callbackUrl = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CALLBACK_URL);

            accessTokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).
                    setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientId).setClientSecret(clientSecret).
                    setRedirectURI(callbackUrl).setCode(authzResponse.getCode()).buildBodyMessage();

            if (accessTokenRequest != null) {
                String serverURL = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                accessTokenRequest.addHeader(UAEPassAuthenticatorConstants.UAE.HTTP_ORIGIN_HEADER, serverURL);
            }

        } catch (OAuthSystemException e) {
            LOG.error("Unable to build the request with request's body attributes.");
            throw new UAEPassAuthnFailedException("Exception while building access token request "
                    + "with the request body", e);
        } catch (URLBuilderException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Unable to identify common-auth URL on browser");
            }
            throw new UAEPassAuthnFailedException("Error occurred while extracting the absolute public " +
                    "URL from browser.", e);
        }

        return accessTokenRequest;
    }

    /**
     * Returns the OAuth type response to the back channel.
     *
     * @param oAuthClient                   OAuth client object received to the authenticator.
     * @param accessRequest                 OAuth client request received by the authenticator.
     * @return OAuthClientResponse          Returns the OAuth client response from the authenticator.
     * @throws UAEPassAuthnFailedException  UAEPassAuthnFailedException will throw to the processAuthenticationResponse.
     */
    public OAuthClientResponse getOAuthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws UAEPassAuthnFailedException {

        OAuthClientResponse oAuthResponse = null;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("UAEPass OAuth client response failed.");
            }
            throw new UAEPassAuthnFailedException("Unable to return OAuth client response.", e);
        }

        return oAuthResponse;
    }

    /**
     * This method specifies the OIDC to the state parameter.
     *
     * @param request  The request that is received by the authenticator.
     * @return String  Returns the login type of the authenticator.
     */
    public String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(UAEPassAuthenticatorConstants.UAE.OAUTH2_PARAM_STATE);
        if (StringUtils.isNotBlank(state)) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Empty split elements in state");
            LOG.debug("Received request path info : " + request.getPathInfo());
        }
        return null;
    }

    /**
     * This method is used to modify commonAuth logout URL, where ever relevant to WSO2 Identity Server.
     * This method will append the state parameter to redirect_uri's value as a query string.
     *
     * @param logOutUri  Logout URI with 02 query parameters (state and logout redirect_uri)
     * @return String    Logout URI with 01 query parameter (redirect_uri)
     */
    public String modifyLogoutUrl(String logOutUri) {

        return logOutUri.replace('&', '?');
    }

    /**
     * Returns the Authorize URL of the UAEPass based on selected environment. First this method checks the if there is
     * a valid key in the XML file configs. Otherwise, it will pick the default URL.
     *
     * @param envUAEPass  The selected UAEPass Environment. (Staging / Production)
     * @return String     The Value of the Authorize endpoint relevant to Staging / Production.
     */
    public String getAuthorizeUrl(String envUAEPass) {

        if (StringUtils.equals(envUAEPass, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING)) {
            if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                    Endpoints.StagingEndpointKeys.UAEPASS_STG_AUTHZ_ENDPOINT_KEY))) {
                return UAEPassAuthenticatorConstants.Endpoints.StagingEndpointValues.UAEPASS_STG_AUTHZ_ENDPOINT_VALUE;
            } else {
                return getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                        Endpoints.StagingEndpointKeys.UAEPASS_STG_AUTHZ_ENDPOINT_KEY);
            }
        } else {
            if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                    Endpoints.ProductionEndpointKeys.UAEPASS_PROD_AUTHZ_ENDPOINT_KEY))) {
                return UAEPassAuthenticatorConstants.Endpoints.ProductionEndpointValues.
                        UAEPASS_PROD_AUTHZ_ENDPOINT_VALUE;
            } else {
                return getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                        Endpoints.ProductionEndpointKeys.UAEPASS_PROD_AUTHZ_ENDPOINT_KEY);
            }
        }
    }

    /**
     * Returns the Token URL of the UAEPass based on selected environment. First this method checks the if there is
     * a valid key in the XML file configs. Otherwise, it will pick the default URL.
     *
     * @param envUAEPass  The selected UAEPass Environment. (Staging / Production)
     * @return String     The Value of the Token endpoint relevant to Staging/Production.
     */
    public String getTokenUrl(String envUAEPass) {

        if (StringUtils.equals(envUAEPass, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING)) {
            if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                    Endpoints.StagingEndpointKeys.UAEPASS_STG_TOKEN_ENDPOINT_KEY))) {
                return UAEPassAuthenticatorConstants.Endpoints.StagingEndpointValues.UAEPASS_STG_TOKEN_ENDPOINT_VALUE;
            } else {
                return getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                        Endpoints.StagingEndpointKeys.UAEPASS_STG_TOKEN_ENDPOINT_KEY);
            }
        } else {
            if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                    Endpoints.ProductionEndpointKeys.UAEPASS_PROD_TOKEN_ENDPOINT_KEY))) {
                return UAEPassAuthenticatorConstants.Endpoints.ProductionEndpointValues.
                        UAEPASS_PROD_TOKEN_ENDPOINT_VALUE;
            } else {
                return getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                        Endpoints.ProductionEndpointKeys.UAEPASS_PROD_TOKEN_ENDPOINT_KEY);
            }
        }

    }

    /**
     * Returns the UserInfo URL of the UAEPass based on selected environment. First this method checks the if there is
     * a valid key in the XML file configs. Otherwise, it will pick the default URL.
     *
     * @param envUAEPass  The selected UAEPass Environment. (Staging / Production)
     * @return String     The Value of the UserInfo endpoint relevant to Staging/Production.
     */
    public String getUserInfoUrl(String envUAEPass) {

        if (StringUtils.equals(envUAEPass, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING)) {
            if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                    Endpoints.StagingEndpointKeys.UAEPASS_STG_USER_INFO_ENDPOINT_KEY))) {
                return UAEPassAuthenticatorConstants.Endpoints.StagingEndpointValues.
                        UAEPASS_STG_USER_INFO_ENDPOINT_VALUE;
            } else {
                return getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                        Endpoints.StagingEndpointKeys.UAEPASS_STG_USER_INFO_ENDPOINT_KEY);
            }
        } else {
            if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                    Endpoints.ProductionEndpointKeys.UAEPASS_PROD_USER_INFO_ENDPOINT_KEY))) {
                return UAEPassAuthenticatorConstants.Endpoints.ProductionEndpointValues.
                        UAEPASS_PROD_USER_INFO_ENDPOINT_VALUE;
            } else {
                return getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                        Endpoints.ProductionEndpointKeys.UAEPASS_PROD_USER_INFO_ENDPOINT_KEY);
            }
        }
    }

    /**
     * Returns the Logout URL of the UAEPass based on selected environment. First this method checks the if there is
     * a valid key in the XML file configs. Otherwise, it will pick the default URL.
     *
     * @param envUAEPass  The selected UAEPass Environment. (Staging / Production)
     * @return String     The Value of the Logout endpoint relevant to Staging/Production.
     */
    public String getLogoutUrl(String envUAEPass) {

        if (StringUtils.equals(envUAEPass, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING)) {
            if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                    Endpoints.StagingEndpointKeys.UAEPASS_STG_LOGOUT_ENDPOINT_KEY))) {
                return UAEPassAuthenticatorConstants.Endpoints.StagingEndpointValues.UAEPASS_STG_LOGOUT_ENDPOINT_VALUE;
            } else {
                return getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                        Endpoints.StagingEndpointKeys.UAEPASS_STG_LOGOUT_ENDPOINT_KEY);
            }
        } else {
            if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                    Endpoints.ProductionEndpointKeys.UAEPASS_PROD_LOGOUT_ENDPOINT_KEY))) {
                return UAEPassAuthenticatorConstants.Endpoints.ProductionEndpointValues.
                        UAEPASS_PROD_LOGOUT_ENDPOINT_VALUE;
            } else {
                return getAuthenticatorConfig().getParameterMap().get(UAEPassAuthenticatorConstants.
                        Endpoints.ProductionEndpointKeys.UAEPASS_PROD_LOGOUT_ENDPOINT_KEY);
            }
        }
    }

    /**
     * Allow to select the UAEPass Env to be used. By default, env would pick according to the client id.
     *
     * @param context       The Authentication context received by authenticator.
     * @return String       Returns the selected environment. (Staging / Production)
     */
    public String getUAEPassEnvironment(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        if (isStagingEnvSelected(context)) {
            return UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING;
        } else {
            if (StringUtils.equals(authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CLIENT_ID),
                    UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.SANDBOX_STAGE_CLIENT_ID)) {
                return UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING;
            } else {
                return UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.PRODUCTION;
            }
        }
    }

    /**
     * Map the JSON payload attributes as key value pairs.
     *
     * @param jwtAttributeSet        A JSON literal object of user claims retrieved by userinfo endpoint/decoded by
     *                               id token.
     * @return Map<String, Object>   Map object of key value pairs of the logged user.
     */
    public Map<String, Object> buildJSON(Set<Map.Entry<String, Object>> jwtAttributeSet) {

        Map<String, Object> jwtAttributeMap = new HashMap<String, Object>();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
            if (LOG.isDebugEnabled()) {
                LOG.debug("UAEPass user claim : " + entry.getKey());
            }
        }
        return jwtAttributeMap;
    }

    /**
     * Checks whether the Staging environment has picked by the authenticator.
     *
     * @param context   The Authentication context received by authenticator.
     * @return Boolean  Staging environment has selected or not by the authenticator.
     */
    public boolean isStagingEnvSelected(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        return Boolean.parseBoolean(authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.UAEPASS_ENV));
    }

    /**
     * Checks whether the logout option has enabled by the authenticator.
     *
     * @param context   The Authentication context received by authenticator.
     * @return Boolean  Logout option has enabled or not by the authenticator.
     */
    public boolean isLogoutEnabled(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        return Boolean.parseBoolean(authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.LOGOUT_ENABLE));
    }
}
