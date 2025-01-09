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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.NativeSDKBasedFederatedOAuthClientResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCTokenValidationUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.authenticator.uaepass.exception.UAEPassAuthnFailedException;
import org.wso2.carbon.identity.authenticator.uaepass.exception.UAEPassUserInfoFailedException;
import org.wso2.carbon.identity.authenticator.uaepass.internal.UAEPassDataHolder;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;
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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.ACCESS_TOKEN_PARAM;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.AUTHENTICATION_ERROR_PAGE_URL;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.AUTHENTICATORS_QUERY_PARAM;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.AUTHENTICATOR_I18N_KEY;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.AUTHENTICATOR_MESSAGE;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.CANCELLED_ON_APP_ERROR;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.ERROR_INVALID_REQUEST_QUERY_PARAMS;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.ERROR_USER_CANCELLED_QUERY_PARAMS;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.ID_TOKEN_PARAM;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.UAE.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.authenticator.uaepass.UAEPassAuthenticatorConstants.UAE.OAUTH2_PARAM_STATE;

/**
 * The UAEPassAuthenticator class contains all the functional tasks handled by the authenticator with UAEPass IdP and
 * WSO2 Identity Server, such as obtaining an authorization code and access token, federated logout with
 * commonauthLogout of the UAEPAss, claim mapping via both id token and user info, UAEPAss Environment
 * selection (Staging / Production), and obtaining user input data.
 */
public class UAEPassAuthenticator extends OpenIDConnectAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(UAEPassAuthenticator.class);
    private static final String DYNAMIC_PARAMS_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static final Pattern PATTERN = Pattern.compile(DYNAMIC_PARAMS_LOOKUP_REGEX);
    private static final Pattern AUTH_PARAM_PATTERN = Pattern.compile(
            OIDCAuthenticatorConstants.DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX);

    /**
     * Checks whether the request and response can be handled by the authenticator.
     *
     * @param request  The request that is received by the authenticator.
     * @return Boolean Whether the request can be handled by the authenticator.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        return isNativeSDKBasedFederationCall(request) ||
                UAEPassAuthenticatorConstants.UAE.LOGIN_TYPE.equals(getLoginType(request));
    }

    /**
     * Returns authenticator's friendly name.
     *
     * @return String  The display name of the authenticator.
     */
    @Override
    public String getFriendlyName() {

        return UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_FRIENDLY_NAME;
    }

    /**
     * Returns the authenticator's name.
     *
     * @return String  The identifier of the authenticator.
     */
    @Override
    public String getName() {

        return UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_NAME;
    }

    /**
     * Returns all user input fields of the authenticator.
     *
     * @return List  Returns the federated authenticator properties.
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
        callbackUrl.setDescription("Enter value corresponding to callback url.");
        callbackUrl.setType(UAEPassAuthenticatorConstants.UAEPassPropertyConstants.TEXTBOX);
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property additionalQueryParams = new Property();
        additionalQueryParams.setName(UAEPassAuthenticatorConstants.UAE.QUERY_PARAMS);
        additionalQueryParams.setDisplayName("Additional Query Parameters");
        additionalQueryParams.setRequired(false);
        additionalQueryParams.setDescription("Enter the additional query parameters.");
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

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // If a logout flow.
        if (context.isLogoutRequest()) {
            return processLogout(request, response, context);
        }
        // If an authentication flow.
        if ((!canHandle(request)
                || Boolean.TRUE.equals(request.getAttribute(FrameworkConstants.REQ_ATTR_HANDLED)))) {
            if (getName().equals(context.getProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR))) {
                context.setRetrying(true);
            }
            initiateAuthenticationRequest(request, response, context);
            context.setCurrentAuthenticator(getName());
            context.setRetrying(false);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
        try {
            processAuthenticationResponse(request, response, context);
            if (getName().equals(context.getProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR))) {
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
            request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, true);
            context.setProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR, null);
            publishAuthenticationStepAttempt(request, context, context.getSubject(), true);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;

        } catch (AuthenticationFailedException e) {
            publishAuthenticationStepAttemptFailure(request, context, e.getUser(), e.getErrorCode());
            request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, true);
            // Decide whether we need to redirect to the login page to retry authentication.
            boolean sendToMultiOptionPage =
                    isStepHasMultiOption(context) && isRedirectToMultiOptionPageOnFailure();
            context.setSendToMultiOptionPage(sendToMultiOptionPage);
            context.setRetrying(retryAuthenticationEnabled());
            context.setProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR, getName());
            throw e;
        }
    }


    private AuthenticatorFlowStatus processLogout(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context) throws LogoutFailedException {
        try {
            if (!canHandle(request)) {
                context.setCurrentAuthenticator(getName());
                initiateLogoutRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                processLogoutResponse(request, response, context);
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } catch (UnsupportedOperationException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Ignoring UnsupportedOperationException.", e);
            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
    }

    private void publishAuthenticationStepAttemptFailure(HttpServletRequest request, AuthenticationContext context,
                                                         User user, String errorCode) {

        context.setAnalyticsData(FrameworkConstants.AnalyticsData.CURRENT_AUTHENTICATOR_ERROR_CODE, errorCode);
        publishAuthenticationStepAttempt(request, context, user, false);
    }

    /**
     * Redirects the user to the login page for authentication purposes. This authenticator redirects the user to the
     * application's login page, which is set up on the UAE Pass side, which works as the external Identity Provider.
     *
     * @param request                          The request that is received by the authenticator.
     * @param response                         Appends the authorized URL once a valid authorized URL is built.
     * @param context                          The Authentication context received by the authenticator.
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
                String callBackUrl = getCallbackUrl(request, authenticatorProperties, context);

                String state = getStateParameter(request, context);
                context.setProperty(getName() + UAEPassAuthenticatorConstants.STATE_PARAM_SUFFIX, state);

                OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).
                        setClientId(clientId).setRedirectURI(callBackUrl).
                        setResponseType(OAUTH2_GRANT_TYPE_CODE).setState(state).
                        buildQueryMessage();

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authorization request contains the compulsory query parameters.");
                }
                String loginPage = authzRequest.getLocationUri();

                if (StringUtils.isNotBlank(authenticatorProperties.get(UAEPassAuthenticatorConstants.
                        UAE.QUERY_PARAMS))) {
                    loginPage = processAdditionalQueryParamSeperation(authenticatorProperties, loginPage,
                            request.getParameterMap(), context);
                } else {
                    Map<String, String> paramMap = new HashMap<>();
                    paramMap.put(UAEPassAuthenticatorConstants.UAE.ACR_VALUES,
                            UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.DEFAULT_ACR_VALUES);
                    paramMap.put(UAEPassAuthenticatorConstants.UAE.SCOPE,
                            UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.DEFAULT_SCOPES);
                    addScopeToContext(context, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.DEFAULT_SCOPES);
                    loginPage = FrameworkUtils.buildURLWithQueryParams(loginPage, paramMap);
                }

                context.setProperty(getName() + UAEPassAuthenticatorConstants.REDIRECT_URL_SUFFIX, loginPage);
                response.sendRedirect(loginPage);
            } else {
                setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages
                        .RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED, context);
                throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages
                        .RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getMessage());
            }

        } catch (UAEPassAuthnFailedException e) {
            setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_PROCESSING_ADDITIONAL_QUERY_PARAMS, context);
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_PROCESSING_ADDITIONAL_QUERY_PARAMS.getCode(), UAEPassAuthenticatorConstants.
                    ErrorMessages.AUTHENTICATION_FAILED_PROCESSING_ADDITIONAL_QUERY_PARAMS.getMessage(), e);
        } catch (IOException e) {
            setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_ENV_SELECTION, context);
            LOG.error("Authorization request building failed.");
            throw new AuthenticationFailedException(
                    UAEPassAuthenticatorConstants.ErrorMessages.AUTHENTICATION_FAILED_ENV_SELECTION.getCode(),
                    UAEPassAuthenticatorConstants.ErrorMessages.AUTHENTICATION_FAILED_ENV_SELECTION.getMessage(), e);
        } catch (OAuthSystemException e) {
            setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_COMPULSORY_QUERY_PARAM_FAILURE, context);
            LOG.error("Unable to build the request with compulsory query parameters.");
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_COMPULSORY_QUERY_PARAM_FAILURE.getCode(), UAEPassAuthenticatorConstants.
                    ErrorMessages.AUTHENTICATION_FAILED_COMPULSORY_QUERY_PARAM_FAILURE.getMessage(), e);
        }
    }

    /**
     * Implements the logic of user authentication with the UAEPass.
     *
     * @param request                         The request that is received by the authenticator.
     * @param response                        The response that is received to the authenticator.
     * @param context                         The Authentication context received by authenticator.
     * @throws AuthenticationFailedException  Exception while creating the access token or id token.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            OAuthClientResponse oAuthResponse;
            if (isTrustedTokenIssuer(context) && isNativeSDKBasedFederationCall(request)) {
                oAuthResponse = getTokensForNativeAPIBasedAuthCall(request, context);
            } else {
                OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
                OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);
                OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
                oAuthResponse = getOAuthResponse(oAuthClient, accessTokenRequest);
            }

            String accessToken = oAuthResponse.getParam(UAEPassAuthenticatorConstants.UAE.ACCESS_TOKEN);
            if (StringUtils.isBlank(accessToken)) {
                setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.
                        ErrorMessages.ACCESS_TOKEN_EMPTY, context);
                throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.
                        ErrorMessages.ACCESS_TOKEN_EMPTY.getMessage());
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

            String authenticatedUserId = getAuthenticatedUserId(jsonClaimMap);
            String attributeSeparator = getMultiAttributeSeparator(context, authenticatedUserId);

            jsonClaimMap.entrySet().stream().filter(entry -> !ArrayUtils.contains(UAEPassAuthenticatorConstants.
                            UAEPassRuntimeConstants.NON_USER_ATTRIBUTES, entry.getKey())).
                    forEach(entry -> buildClaimMappings(claims, entry, attributeSeparator));

            if (StringUtils.isBlank(authenticatedUserId)) {
                setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages.
                        USER_ID_NOT_FOUND_IN_ID_TOKEN, context);
                throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                        USER_ID_NOT_FOUND_IN_ID_TOKEN.getMessage());
            }
            authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier
                    (authenticatedUserId);
            authenticatedUser.setUserAttributes(claims);
            context.setSubject(authenticatedUser);

        } catch (UAEPassAuthnFailedException e) {
            setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_RETRIEVING_OAUTH_CLIENT_RESPONSE, context);
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_RETRIEVING_OAUTH_CLIENT_RESPONSE.getCode(), UAEPassAuthenticatorConstants.
                    ErrorMessages.AUTHENTICATION_FAILED_RETRIEVING_OAUTH_CLIENT_RESPONSE.getMessage(), e);
        } catch (UAEPassUserInfoFailedException e) {
            setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_ACCESS_TOKEN_REQUEST_FAILURE, context);
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_ACCESS_TOKEN_REQUEST_FAILURE.getCode(), UAEPassAuthenticatorConstants.
                    ErrorMessages.AUTHENTICATION_FAILED_ACCESS_TOKEN_REQUEST_FAILURE.getMessage(), e);
        } catch (OAuthProblemException e) {
            LOG.error("OAuth authorize response failure.");
            setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_AUTHORIZED_RESPONSE_FAILURE, context);
            if (e.getMessage().contains(CANCELLED_ON_APP_ERROR)) {
                context.setProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR, getName());
                redirectToErrorPage(response, ERROR_USER_CANCELLED_QUERY_PARAMS);
            } else {
                context.setProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR, getName());
                redirectToErrorPage(response, ERROR_INVALID_REQUEST_QUERY_PARAMS);
            }
        }
    }

    private void redirectToErrorPage(HttpServletResponse response, String errorMessage)
            throws AuthenticationFailedException {

        try {
            String queryString = AUTHENTICATORS_QUERY_PARAM + getName() + errorMessage;
            String errorPage = getErrorPageURL();
            String url = FrameworkUtils.appendQueryParamsStringToUrl(errorPage, queryString);
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    AUTHENTICATION_FAILED_AUTHORIZED_RESPONSE_FAILURE.getCode(), UAEPassAuthenticatorConstants.
                    ErrorMessages.AUTHENTICATION_FAILED_AUTHORIZED_RESPONSE_FAILURE.getMessage(), e);
        }
    }


    private String getErrorPageURL() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create().addPath(AUTHENTICATION_ERROR_PAGE_URL)
                    .build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building UAE Pass error page URL", e);
        }
    }

    /**
     * Logout initialization will be handled by this method. This includes the functionality to support
     * common-auth logout of the UAEPass.
     * API based logout is not supported.
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

        if (isAPIBasedAuthenticationFlow(request, context)) {
            LOG.debug("API based logout flow is not supported.");
            return;
        }
        if (isLogoutEnabled(context)) {
            try {
                Map<String, String> paramMap = new HashMap<>();
                Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

                String callbackURI = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CALLBACK_URL);
                String sessionID = context.getContextIdentifier() + "," + UAEPassAuthenticatorConstants.UAE.LOGIN_TYPE;
                paramMap.put(UAEPassAuthenticatorConstants.UAE.OAUTH2_PARAM_STATE, sessionID);

                String envUAEPass = getUAEPassEnvironment(context);
                String logoutEndpoint = getLogoutUrl(envUAEPass);

                String redirectURI = FrameworkUtils.buildURLWithQueryParams(callbackURI, paramMap);
                paramMap.clear();
                paramMap.put(UAEPassAuthenticatorConstants.UAE.REDIRECT_URI, redirectURI);
                String logoutUrl = FrameworkUtils.buildURLWithQueryParams(logoutEndpoint, paramMap);
                response.sendRedirect(logoutUrl);

            } catch (IllegalArgumentException | IOException e) {
                String idpName = context.getExternalIdP().getName();
                String tenantDomain = context.getTenantDomain();
                LOG.error("Error in initiate logout URI build in IdP " + idpName + "at tenant domain " + tenantDomain);
                throw new LogoutFailedException("Error occurred while initiating the logout request to IdP: " + idpName
                        + " of tenantDomain: " + tenantDomain, e);
            }
        } else {
            super.initiateLogoutRequest(request, response, context);
        }
    }

    /**
     * Returns the user id of the authenticated user.
     *
     * @param userClaims                      The Map object with user claims returns from buildJSON.
     * @return String                         The ID of the authenticated user from UAEPass.
     * @throws AuthenticationFailedException  Throws an AuthenticationFailedException exception to
     *                                        processAuthenticationResponse.
     */
    protected String getAuthenticatedUserId(Map<String, Object> userClaims)
            throws AuthenticationFailedException {

        String authenticatedUserId;
        authenticatedUserId = (String) userClaims.get(UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.SUB);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
            }
        if (StringUtils.isBlank(authenticatedUserId)) {
            LOG.error("The authenticated user id is empty.");
            throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getCode(),
                    UAEPassAuthenticatorConstants.ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.
                            getMessage());
        }

        return authenticatedUserId;
    }

    /**
     * Map the non-user claim values according to the attribute separator.
     *
     * @param claims     Retrieved JSON claim set from id token / userinfo endpoint of UAEPass.
     * @param entry      A collective view of JSON claims without non-user attributes.
     * @param separator  The attribute separator obtained from getMultiAttributeSeparator method.
     */
    protected void buildClaimMappings(Map<ClaimMapping, String> claims, Map.Entry<String, Object> entry,
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
     * @return String                         The element which is used to separate the attributes from the
     *                                        JSON payload.
     * @throws AuthenticationFailedException  Throw an Authentication failed exception.
     */
    protected String getMultiAttributeSeparator(AuthenticationContext context, String authenticatedUserId)
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
     * @param context  The Authentication context received by authenticator.
     * @param idToken  The received ID token from the processAuthenticationResponse.
     * @return Map     Decoded JWT payload via JSON Key value pairs.
     */
    protected Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(UAEPassAuthenticatorConstants.UAE.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parse(new String(decoded)).entrySet();
        } catch (ParseException e) {
            LOG.error("Error occurred while parsing JWT ID token provided by UAEPass.", e);
        }
        Map<String, Object> idTokenJwtAttributes = buildJSON(jwtAttributeSet);

        return idTokenJwtAttributes;
    }

    /**
     * Request the access token - Create a request to access token endpoint of the external IdP.
     *
     * @param context                       The Authentication context received by authenticator.
     * @param authzResponse                 The response from to authorize endpoint. (To get the received
     *                                      authorize code.)
     * @return OAuthClientRequest           Returns the access token call which was built.
     * @throws UAEPassAuthnFailedException  Exception throws if unable to process the token request.
     */
    protected OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse authzResponse)
            throws UAEPassAuthnFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        OAuthClientRequest accessTokenRequest = null;
        try {
            String envUAEPass = getUAEPassEnvironment(context);
            String clientId = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CLIENT_SECRET);
            String tokenEndPoint = getTokenUrl(envUAEPass);
            String callbackUrl = getCallbackUrl(null, authenticatorProperties, context);

            accessTokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).
                    setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientId).setClientSecret(clientSecret).
                    setRedirectURI(callbackUrl).setCode(authzResponse.getCode()).buildBodyMessage();

            if (accessTokenRequest != null) {
                String serverURL = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                accessTokenRequest.addHeader(UAEPassAuthenticatorConstants.UAE.HTTP_ORIGIN_HEADER, serverURL);
            }

        } catch (OAuthSystemException e) {
            LOG.error("Unable to build the request with request's body attributes.");
            throw new UAEPassAuthnFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    UAEPASS_AUTHN_FAILED_ACCESS_TOKEN_BUILD_FAILURE.getCode(), UAEPassAuthenticatorConstants.
                    ErrorMessages.UAEPASS_AUTHN_FAILED_ACCESS_TOKEN_BUILD_FAILURE.getMessage(), e);
        } catch (URLBuilderException e) {
            LOG.error("Unable to identify common-auth URL on browser.");
            throw new UAEPassAuthnFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    UAEPASS_AUTHN_FAILED_ABSOLUTE_URL_BUILD_FAILURE.getCode(), UAEPassAuthenticatorConstants.
                    ErrorMessages.UAEPASS_AUTHN_FAILED_ABSOLUTE_URL_BUILD_FAILURE.getMessage(), e);
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
    protected OAuthClientResponse getOAuthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws UAEPassAuthnFailedException {

        OAuthClientResponse oAuthResponse = null;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            LOG.error("UAEPass OAuth client response failed.");
            throw new UAEPassAuthnFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    UAEPASS_AUTHN_FAILED_EXCEPTION.getCode(),
                    UAEPassAuthenticatorConstants.ErrorMessages.UAEPASS_AUTHN_FAILED_EXCEPTION.getMessage(), e);
        }

        return oAuthResponse;
    }

    /**
     * This method specifies the OIDC to the state parameter.
     *
     * @param request  The request that is received by the authenticator.
     * @return String  Returns the login type of the authenticator.
     */
    protected String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(UAEPassAuthenticatorConstants.UAE.OAUTH2_PARAM_STATE);
        if (StringUtils.isNotBlank(state)) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Empty split elements in state. Received request path info : " + request.getPathInfo());
        }
        return null;
    }

    /**
     * Replaces dynamic parameters in the query string with their corresponding values from the provided parameters map.
     *
     * @param context     Authentication context.
     * @param queryString The query string containing dynamic parameters in the format ${parameterName}.
     * @param parameters  A map of parameter names to their values.
     * @return The query string with dynamic parameters replaced by their corresponding values.
     */
    private String resolveDynamicParams(AuthenticationContext context, String queryString,
                                        Map<String, String[]> parameters) {

        if (queryString.contains(OIDCAuthenticatorConstants.AUTH_PARAM)) {
            queryString = resolveAuthenticatorParams(context, queryString);
        }
        Matcher matcher = PATTERN.matcher(queryString);
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = parameters.containsKey(name) ? parameters.get(name)[0] : StringUtils.EMPTY;
            queryString = queryString.replaceAll("\\$\\{" + name + "}", Matcher.quoteReplacement(value));
            if (LOG.isDebugEnabled()) {
                LOG.debug ("interpretQueryString " + name + " <" + value + "> as <" + queryString + ">");
            }
        }
        return queryString;
    }

    /**
     * To capture the additional authenticator params from the adaptive script and interpret the query string with
     * additional params.
     *
     * @param context     Authentication context.
     * @param queryString the query string with additional param.
     * @return interpreted query string.
     */
    private String resolveAuthenticatorParams(AuthenticationContext context, String queryString) {

        Matcher matcher = AUTH_PARAM_PATTERN.matcher(queryString);
        Map<String, String> runtimeParams = getRuntimeParams(context);
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = runtimeParams.getOrDefault(name, StringUtils.EMPTY);
            queryString = queryString.replaceAll("\\$authparam\\{" + name + "}", Matcher.quoteReplacement(value));
            if (LOG.isDebugEnabled()) {
                LOG.debug ("interpretQueryString " + name + " <" + value + "> as <" + queryString + ">");
            }
        }
        return queryString;
    }

    /**
     * This method is used to add additional parameters along with the authorize request.
     *
     * @param authenticatorProperties  The user input fields of the authenticator.
     * @param loginPage                Current authorize URL.
     * @param requestParams        The request parameters received by the authenticator.
     * @return The modified authorized URL appending the additional query params.
     */
    private String processAdditionalQueryParamSeperation(Map<String, String> authenticatorProperties, String
            loginPage, Map<String,String[]> requestParams, AuthenticationContext context)
            throws UAEPassAuthnFailedException {

        String additionalQueryParams = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.QUERY_PARAMS);
        additionalQueryParams = resolveDynamicParams(context, additionalQueryParams, requestParams);
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
            // Skip query parameters with empty values.
            if (keyValuePairs.length > 1) {
                paramMap.put(keyValuePairs[0], keyValuePairs[1]);
            }
        }
        if (paramMap.containsKey(UAEPassAuthenticatorConstants.UAE.SCOPE)) {
            addScopeToContext(context, paramMap.get(UAEPassAuthenticatorConstants.UAE.SCOPE));
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
                addScopeToContext(context, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.DEFAULT_SCOPES);
            }

            finalAuthzUrl = FrameworkUtils.buildURLWithQueryParams(loginPage, paramMap);
        } catch (IllegalArgumentException | UnsupportedEncodingException e) {
            LOG.error("Authorize URL creation failed due to an issue of additional query parameters.");
            throw new UAEPassAuthnFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                    UAEPASS_AUTHEN_FAILED_PROCESSING_ADDITIONAL_QUERY_PARAMS.getCode(), UAEPassAuthenticatorConstants.
                    ErrorMessages.UAEPASS_AUTHEN_FAILED_PROCESSING_ADDITIONAL_QUERY_PARAMS.getMessage(), e);
        }

        return finalAuthzUrl;
    }

    /**
     * This method is used to retrieve user claims as key value pairs to the Java Map object from user info endpoint.
     *
     * @param oAuthResponse         The response from OAuthClient to authenticator by the UAEPass.
     *                              (Use to get the access token.)
     * @param context               The Authentication context received by authenticator.
     * @return Map<String, Object>  Map object of key value pairs of the logged user.
     */
    private Map<String, Object> getUserInfoUserAttributes(OAuthClientResponse oAuthResponse,
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
            LOG.error("Error occurred while parsing user info payload by UAEPass.");
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
    private String sendUserInfoRequest(AuthenticationContext context, String accessToken)
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
            LOG.error("Unable to retrieve successful response from UAEPass UserInfo.");
            throw new UAEPassUserInfoFailedException("UAEPass UserInfo failure.", e);
        }
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            LOG.debug("response: " + builder);
        }

        return builder.toString();
    }

    /**
     * Returns the authorize endpoint of the UAEPass based on selected environment.
     * First this method will check if there is a valid key in the XML file configs. else, it will pick the default.
     *
     * @param envUAEPass  The selected UAEPass Environment. (Staging / Production)
     * @return String     The Value of the Authorize endpoint relevant to Staging / Production.
     */
    private String getAuthorizeUrl(String envUAEPass) {

        if (StringUtils.equals(envUAEPass, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING)) {
            if (isFileConfigEmpty(UAEPassAuthenticatorConstants.
                    Endpoints.StagingEndpointKeys.UAEPASS_STG_AUTHZ_ENDPOINT_KEY)) {
                return UAEPassAuthenticatorConstants.Endpoints.StagingEndpointValues.UAEPASS_STG_AUTHZ_ENDPOINT_VALUE;
            } else {
                return getFileConfigValue(UAEPassAuthenticatorConstants.
                        Endpoints.StagingEndpointKeys.UAEPASS_STG_AUTHZ_ENDPOINT_KEY);
            }
        } else {
            if (isFileConfigEmpty(UAEPassAuthenticatorConstants.
                    Endpoints.ProductionEndpointKeys.UAEPASS_PROD_AUTHZ_ENDPOINT_KEY)) {
                return UAEPassAuthenticatorConstants.Endpoints.ProductionEndpointValues.
                        UAEPASS_PROD_AUTHZ_ENDPOINT_VALUE;
            } else {
                return getFileConfigValue(UAEPassAuthenticatorConstants.
                        Endpoints.ProductionEndpointKeys.UAEPASS_PROD_AUTHZ_ENDPOINT_KEY);
            }
        }
    }

    /**
     * Returns the token endpoint of the UAEPass based on selected environment.
     * First this method will check if there is a valid key in the XML file configs. else, it will pick the default.
     *
     * @param envUAEPass  The selected UAEPass Environment. (Staging / Production)
     * @return String     The Value of the Token endpoint relevant to Staging/Production.
     */
    private String getTokenUrl(String envUAEPass) {

        if (StringUtils.equals(envUAEPass, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING)) {
            if (isFileConfigEmpty(UAEPassAuthenticatorConstants.
                    Endpoints.StagingEndpointKeys.UAEPASS_STG_TOKEN_ENDPOINT_KEY)) {
                return UAEPassAuthenticatorConstants.Endpoints.StagingEndpointValues.UAEPASS_STG_TOKEN_ENDPOINT_VALUE;
            } else {
                return getFileConfigValue(UAEPassAuthenticatorConstants.
                        Endpoints.StagingEndpointKeys.UAEPASS_STG_TOKEN_ENDPOINT_KEY);
            }
        } else {
            if (isFileConfigEmpty(UAEPassAuthenticatorConstants.
                    Endpoints.ProductionEndpointKeys.UAEPASS_PROD_TOKEN_ENDPOINT_KEY)) {
                return UAEPassAuthenticatorConstants.Endpoints.ProductionEndpointValues.
                        UAEPASS_PROD_TOKEN_ENDPOINT_VALUE;
            } else {
                return getFileConfigValue(UAEPassAuthenticatorConstants.
                        Endpoints.ProductionEndpointKeys.UAEPASS_PROD_TOKEN_ENDPOINT_KEY);
            }
        }

    }

    /**
     * Returns the user info endpoint of the UAEPass based on selected environment.
     * First this method will check if there is a valid key in the XML file configs. else, it will pick the default.
     *
     * @param envUAEPass  The selected UAEPass Environment. (Staging / Production)
     * @return String     The Value of the UserInfo endpoint relevant to Staging/Production.
     */
    private String getUserInfoUrl(String envUAEPass) {

        if (StringUtils.equals(envUAEPass, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING)) {
            if (isFileConfigEmpty(UAEPassAuthenticatorConstants.
                    Endpoints.StagingEndpointKeys.UAEPASS_STG_USER_INFO_ENDPOINT_KEY)) {
                return UAEPassAuthenticatorConstants.Endpoints.StagingEndpointValues.
                        UAEPASS_STG_USER_INFO_ENDPOINT_VALUE;
            } else {
                return getFileConfigValue(UAEPassAuthenticatorConstants.
                        Endpoints.StagingEndpointKeys.UAEPASS_STG_USER_INFO_ENDPOINT_KEY);
            }
        } else {
            if (isFileConfigEmpty(UAEPassAuthenticatorConstants.
                    Endpoints.ProductionEndpointKeys.UAEPASS_PROD_USER_INFO_ENDPOINT_KEY)) {
                return UAEPassAuthenticatorConstants.Endpoints.ProductionEndpointValues.
                        UAEPASS_PROD_USER_INFO_ENDPOINT_VALUE;
            } else {
                return getFileConfigValue(UAEPassAuthenticatorConstants.
                        Endpoints.ProductionEndpointKeys.UAEPASS_PROD_USER_INFO_ENDPOINT_KEY);
            }
        }
    }

    /**
     * Returns the logout endpoint of the UAEPass based on selected environment.
     * First this method will check if there is a valid key in the XML file configs. else, it will pick the default.
     *
     * @param envUAEPass  The selected UAEPass Environment. (Staging / Production)
     * @return String     The Value of the Logout endpoint relevant to Staging/Production.
     */
    private String getLogoutUrl(String envUAEPass) {

        if (StringUtils.equals(envUAEPass, UAEPassAuthenticatorConstants.UAEPassRuntimeConstants.STAGING)) {
            if (isFileConfigEmpty(UAEPassAuthenticatorConstants.
                    Endpoints.StagingEndpointKeys.UAEPASS_STG_LOGOUT_ENDPOINT_KEY)) {
                return UAEPassAuthenticatorConstants.Endpoints.StagingEndpointValues.UAEPASS_STG_LOGOUT_ENDPOINT_VALUE;
            } else {
                return getFileConfigValue(UAEPassAuthenticatorConstants.
                        Endpoints.StagingEndpointKeys.UAEPASS_STG_LOGOUT_ENDPOINT_KEY);
            }
        } else {
            if (isFileConfigEmpty(UAEPassAuthenticatorConstants.
                    Endpoints.ProductionEndpointKeys.UAEPASS_PROD_LOGOUT_ENDPOINT_KEY)) {
                return UAEPassAuthenticatorConstants.Endpoints.ProductionEndpointValues.
                        UAEPASS_PROD_LOGOUT_ENDPOINT_VALUE;
            } else {
                return getFileConfigValue(UAEPassAuthenticatorConstants.
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
    private String getUAEPassEnvironment(AuthenticationContext context) {

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
    private Map<String, Object> buildJSON(Set<Map.Entry<String, Object>> jwtAttributeSet) {

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
     * Checks whether the Staging environment has been picked by the authenticator.
     *
     * @param context   The Authentication context received by authenticator.
     * @return Boolean  Staging environment has selected or not by the authenticator.
     */
    private boolean isStagingEnvSelected(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        return Boolean.parseBoolean(authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.UAEPASS_ENV));
    }

    /**
     * Checks whether the logout option has been enabled by the authenticator.
     *
     * @param context   The Authentication context received by authenticator.
     * @return Boolean  Logout option has been enabled or not by the authenticator.
     */
    private boolean isLogoutEnabled(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        return Boolean.parseBoolean(authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.LOGOUT_ENABLE));
    }

    /**
     * Checks whether if there is having a toml configuration according to the given config key.
     *
     * @param fileConfigKey  Endpoint key according to the selected UAEPass env.
     * @return Boolean       Returns either true or false the availability of file config.
     */
    private boolean isFileConfigEmpty(String fileConfigKey) {

        return StringUtils.isBlank(getAuthenticatorConfig().getParameterMap().get(fileConfigKey));
    }

    /**
     * Returns the toml configuration values of authenticator's endpoints according to the UAEPAss env.
     *
     * @param fileConfigKey Endpoint key according to the selected UAEPass env.
     * @return String       Returns th endpoint's value.
     */
    private String getFileConfigValue(String fileConfigKey) {

        return getAuthenticatorConfig().getParameterMap().get(fileConfigKey);
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     * If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     * an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setI18nKey(getI18nKey());
        String idpName = context.getExternalIdP().getIdPName();
        authenticatorData.setIdp(idpName);

        List<String> requiredParameterList = new ArrayList<>();
        if (isTrustedTokenIssuer(context)) {
            requiredParameterList.add(ACCESS_TOKEN_PARAM);
            requiredParameterList.add(ID_TOKEN_PARAM);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, true));
        } else {
            requiredParameterList.add(OAUTH2_GRANT_TYPE_CODE);
            requiredParameterList.add(OAUTH2_PARAM_STATE);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, false));
        }
        authenticatorData.setRequiredParams(requiredParameterList);
        if (context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            authenticatorData.setMessage((AuthenticatorMessage) context.getProperty(AUTHENTICATOR_MESSAGE));
        }

        return Optional.of(authenticatorData);
    }

    /**
     * Get the i18n key defined to represent the authenticator name.
     *
     * @return the 118n key.
     */
    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_I18N_KEY;
    }

    private boolean isTrustedTokenIssuer(AuthenticationContext context) {

        ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
        if (externalIdPConfig == null) {
            return false;
        }

        IdentityProvider externalIdentityProvider = externalIdPConfig.getIdentityProvider();
        if (externalIdentityProvider == null) {
            return false;
        }

        IdentityProviderProperty[] identityProviderProperties = externalIdentityProvider.getIdpProperties();
        for (IdentityProviderProperty identityProviderProperty : identityProviderProperties) {
            if (IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER.equals(identityProviderProperty.getName())) {
                return Boolean.parseBoolean(identityProviderProperty.getValue());
            }
        }

        return false;
    }

    private boolean isNativeSDKBasedFederationCall(HttpServletRequest request) {

        return request.getParameter(ACCESS_TOKEN_PARAM) != null && request.getParameter(ID_TOKEN_PARAM) != null;
    }

    private AdditionalData getAdditionalData(AuthenticationContext context, boolean isNativeSDKBasedFederationCall) {

        AdditionalData additionalData = new AdditionalData();
        String currentAuthenticator = getName();

        if (isNativeSDKBasedFederationCall) {
            Map<String, String> additionalAuthenticationParams = new HashMap<>();

            additionalAuthenticationParams.put(UAEPassAuthenticatorConstants.CLIENT_ID_PARAM,
                    context.getAuthenticatorProperties().get(UAEPassAuthenticatorConstants.UAE.CLIENT_ID));
            String scope = (String) context.getProperty(currentAuthenticator +
                    UAEPassAuthenticatorConstants.SCOPE_PARAM_SUFFIX);
            additionalAuthenticationParams.put(UAEPassAuthenticatorConstants.SCOPE, scope);
            additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        } else {
            additionalData.setRedirectUrl((String) context.getProperty(currentAuthenticator +
                    UAEPassAuthenticatorConstants.REDIRECT_URL_SUFFIX));
            Map<String, String> additionalAuthenticationParams = new HashMap<>();
            String state = (String) context.getProperty(currentAuthenticator +
                    UAEPassAuthenticatorConstants.STATE_PARAM_SUFFIX);
            additionalAuthenticationParams.put(UAEPassAuthenticatorConstants.UAE.OAUTH2_PARAM_STATE, state);
            additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        }
        return additionalData;
    }

    private static void setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages errorMessage,
                                                         AuthenticationContext context) {

        AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                AuthenticatorMessageType.ERROR, errorMessage.
                getCode(), errorMessage.getMessage(), null);
        context.setProperty(AUTHENTICATOR_MESSAGE, authenticatorMessage);
    }

    private static void setAuthenticatorMessageToContext(AuthenticatorMessage message,
                                                         AuthenticationContext context) {

        context.setProperty(AUTHENTICATOR_MESSAGE, message);
    }

    private String getStateParameter(HttpServletRequest request, AuthenticationContext context) {

        if (isAPIBasedAuthenticationFlow(request, context)) {
            return UUID.randomUUID() + "," + UAEPassAuthenticatorConstants.UAE.LOGIN_TYPE;
        }

        return context.getContextIdentifier() + "," + UAEPassAuthenticatorConstants.UAE.LOGIN_TYPE;
    }

    /**
     * Returns the callback URL of the IdP Hub.
     *
     * @param authenticatorProperties Authentication properties configured in OIDC federated authenticator
     *                                configuration.
     * @param context                 Authentication context.
     * @return If API based authn flow, returns the redirect URL from the authentication context. If not returns the
     * callback URL configured in OIDC federated authenticator configuration and if it is empty returns
     * /commonauth endpoint URL path as the default value.
     */
    private String getCallbackUrl(HttpServletRequest request, Map<String, String> authenticatorProperties,
                                  AuthenticationContext context) {

        if (isAPIBasedAuthenticationFlow(request, context)) {
            return (String) context.getProperty(UAEPassAuthenticatorConstants.REDIRECT_URL);
        }

        return authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CALLBACK_URL);
    }

    private boolean isAPIBasedAuthenticationFlow(HttpServletRequest request, AuthenticationContext context) {

        if (context != null) {
            return Boolean.parseBoolean((String) context.getProperty(FrameworkConstants.IS_API_BASED));
        }
        return FrameworkUtils.isAPIBasedAuthenticationFlow(request);
    }

    /**
     * Add scopes to the context to be used with App Native Authentication.
     *
     * @param context Authentication context.
     * @param scope Space separated scopes.
     */
    private void addScopeToContext(AuthenticationContext context, String scope) {

        if (StringUtils.isNotBlank(scope)) {
            context.setProperty(getName() + UAEPassAuthenticatorConstants.SCOPE_PARAM_SUFFIX, scope);
        }
    }

    private OAuthClientResponse getTokensForNativeAPIBasedAuthCall(HttpServletRequest request,
                                                               AuthenticationContext context)
            throws AuthenticationFailedException {

        String idToken = request.getParameter(ID_TOKEN_PARAM);
        String accessToken = request.getParameter(ACCESS_TOKEN_PARAM);
        if (StringUtils.isNotBlank(idToken)) {
            try {
                validateJWTToken(context, idToken);
            } catch (Exception e) {
                setAuthenticatorMessageToContext(
                        UAEPassAuthenticatorConstants.ErrorMessages.JWT_TOKEN_VALIDATION_FAILED,
                        context);
                throw new AuthenticationFailedException(UAEPassAuthenticatorConstants.ErrorMessages.
                        JWT_TOKEN_VALIDATION_FAILED.getMessage(), e);
            }
        }
        NativeSDKBasedFederatedOAuthClientResponse nativeSDKBasedFederatedOAuthClientResponse
                = new NativeSDKBasedFederatedOAuthClientResponse();
        nativeSDKBasedFederatedOAuthClientResponse.setAccessToken(accessToken);
        nativeSDKBasedFederatedOAuthClientResponse.setIdToken(idToken);

        return nativeSDKBasedFederatedOAuthClientResponse;
    }

    private void validateJWTToken(AuthenticationContext context, String idToken) throws AuthenticationFailedException,
            IdentityOAuth2Exception, JOSEException, IdentityProviderManagementException, ParseException {

        SignedJWT signedJWT = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        validateAudience(context, claimsSet.getAudience());
        OIDCTokenValidationUtil.validateIssuerClaim(claimsSet);
        String tenantDomain = context.getTenantDomain();
        String idpIdentifier = OIDCTokenValidationUtil.getIssuer(claimsSet);
        IdentityProvider identityProvider = getIdentityProvider(idpIdentifier, tenantDomain);

        if (identityProvider == null) {
            String msg =  String.format(
                    UAEPassAuthenticatorConstants.ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER.getCode(), idpIdentifier);
            AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(
                    FrameworkConstants.AuthenticatorMessageType.ERROR,
                    UAEPassAuthenticatorConstants.ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER.getCode(),
                    msg,
                    null);
            setAuthenticatorMessageToContext(authenticatorMessage, context);
            throw new AuthenticationFailedException(msg);
        }

        OIDCTokenValidationUtil.validateSignature(signedJWT, identityProvider);
    }

    private void validateAudience(AuthenticationContext context, List<String> audience)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(UAEPassAuthenticatorConstants.UAE.CLIENT_ID);
        if (audience == null || !audience.contains(clientId)) {
            setAuthenticatorMessageToContext(UAEPassAuthenticatorConstants.ErrorMessages
                    .ID_TOKEN_AUD_VALIDATION_FAILED, context);
            throw new AuthenticationFailedException(
                    UAEPassAuthenticatorConstants.ErrorMessages.ID_TOKEN_AUD_VALIDATION_FAILED.getMessage());
        }
    }

    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws IdentityProviderManagementException {

        IdentityProvider identityProvider;
        identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);

        if (identityProvider == null) {
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
        }

        return identityProvider;
    }
}
