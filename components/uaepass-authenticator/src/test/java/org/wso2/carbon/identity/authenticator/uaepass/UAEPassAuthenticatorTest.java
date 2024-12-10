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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCTokenValidationUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.SubProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.authenticator.uaepass.exception.UAEPassAuthnFailedException;
import org.wso2.carbon.identity.authenticator.uaepass.internal.UAEPassDataHolder;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;

@PrepareForTest({LogFactory.class, OAuthAuthzResponse.class, OAuthClientRequest.class, UAEPassDataHolder.class,
        URL.class, ServiceURLBuilder.class, OAuthClientResponse.class, IdentityUtil.class, UAEPassAuthenticator.class,
        UAEPassAuthenticatorConstants.class, AbstractApplicationAuthenticator.class, Property.class, Log.class,
        IdentityTenantUtil.class, OIDCTokenValidationUtil.class, IdentityProviderManager.class})
@SuppressStaticInitializationFor({"org.wso2.carbon.idp.mgt.IdentityProviderManager"})
public class UAEPassAuthenticatorTest extends PowerMockTestCase {

    private static final String accessToken = "fd2fffca-b5e2-466d-aac9-207382497b88";
    private static final String idToken = "eyJ4NXQiOiJOVGRtWmpNNFpEazNOalkwWXpjNU1tWm1PRGd3TVRFM01XWXdOREU1TVdSbFpEZzROemM0Wk" +
            "EiLCJraWQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdSbE5qSmtPREZrWkRSaU9U" +
            "RmtNV0ZoTXpVMlpHVmxOZ19SUzI1NiIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiNzgwOE5OTlphN2ZfdHFzaVVzNG5vZyIsInN1Yi" +
            "I6Ijk0NzEyMTg0NTE4IiwiZ2VuZGVyIjoiVW5rbm93biIsImFtciI6WyJVQUVQYXNzQXV0aGVudGljYXRvciIsIkJhc2ljQXV0aGVudGl" +
            "jYXRvciJdLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJtb2JpbGUiOiI5NDcxMjE4NDUxOCIs" +
            "Imxhc3RuYW1lRU4iOiJLYWx1Ym93aWxhIiwiZnVsbG5hbWVFTiI6IkRpbXV3YW5DIEthbHVib3dpbGEiLCJzaWQiOiIxYzMwMTBlOS1iYT" +
            "Q2LTQ1NGMtODVkMS03N2U3ZmIzZTk4N2QiLCJhdWQiOiJ0WFU0RXlsaTRmb0U1SWVuQlZjRGVnTk9mUDBhIiwiY19oYXNoIjoiMXZqRnl" +
            "FR1FicmdFWnoyM0x3SWVJdyIsIm5iZiI6MTY1NzIwNTk0MiwiYXpwIjoidFhVNEV5bGk0Zm9FNUllbkJWY0RlZ05PZlAwYSIsInVzZXJUe" +
            "XBlIjoiU09QMSIsImV4cCI6MTY1NzIwOTU0MiwiaWF0IjoxNjU3MjA1OTQyLCJNdWx0aUF0dHJpYnV0ZVNlcGFyYXRvciI6W10sImVtYWl" +
            "sIjoiZGNrYWx1Ym93aWxhMjUxMzJAZ21haWwuY29tIn0.VM5fxgtpl07oPxd4RNEwW4KvD0rJJV7Lrl9xSIseR2qzoIV3LzZok7Tr9XlLZ" +
            "mx35MRDkQ7ezar8zZtfTXqaOEAeMIbD0a9yMx14NRhjzPA6iBtdCAdKGaua0RVPZDcr7IUAUsJSJ4Q6S4gYWiOfMHXvrB8zqqx9_rWQTk9" +
            "Bxn_LkvgU0tyPu88b8G2fUISFTxXb69rJ1mtTfWH_oFGkwKH9ij4NjHp1P2n09S9fVZNT3v1nsY8B5d1bS5YBrRcgtBtPKhNlsQ_4OFq--" +
            "PMB_OlzZrId6Po9IBarzUrpqY5uzCJGzSk5xAXlxq0jF42xUtAbD5L8CtoESxGMPYRZfg";
    private static Map<String, String> authenticatorProperties;
    private final int TENANT_ID = 1234;
    UAEPassAuthenticator uaePassAuthenticator;
    AuthenticatorConfig mockAuthConfig;
    @Mock
    private HttpServletRequest mockServletRequest;
    @Mock
    private HttpServletResponse mockServletResponse;
    @Mock
    private OAuthClientResponse mockOAuthClientResponse;
    @Mock
    private AuthenticationContext mockAuthenticationContext;
    @Mock
    private UAEPassDataHolder openIDConnectAuthenticatorDataHolder;
    @Mock
    private UAEPassAuthenticator mockUaePassAuthenticator;
    @Mock
    private RealmConfiguration mockRealmConfiguration;
    @Mock
    private OAuthClient mockOAuthClient;
    @Mock
    private RealmService mockRealmService;
    @Mock
    private UserStoreManager mockUserStoreManager;
    @Mock
    private TenantManager mockTenantManger;
    @Mock
    private OAuthAuthzResponse mockOAuthzResponse;
    @Mock
    private OAuthClientRequest mockOAuthClientRequest;
    @Mock
    private OAuthJSONAccessTokenResponse mockOAuthJSONAccessTokenResponse;
    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;
    @Mock
    private ExternalIdPConfig externalIdPConfig;
    @Mock
    private ServiceURLBuilder serviceURLBuilder;
    @Mock
    private ServiceURL serviceURL;
    @Mock
    private UserRealm mockUserRealm;
    private Map<String, String> paramValueMap;
    @Mock
    private IdentityProvider identityProvider;
    @Mock
    private IdentityProviderManager identityProviderManager;

    private static final String SESSION_DATA_KEY = "7b1c8131-c6bd-4682-892e-1a948a9e57e8";
    private static final String CLIENT_ID = "tXU4Eyli4foE5IenBVcDegNOfP0a";
    private static final String SUPER_TENANT = "carbon.super";
    private AuthenticationRequest mockAuthenticationRequest = new AuthenticationRequest();
    private static final String REDIRECT_URL = "https://stg-id.uaepass.ae/idshub/authorize?scope=openid&" +
            "response_type=code&redirect_uri=https%3A%2F%2Flocalhost%3A9443%2Fcommonauth&" +
            "state=958e9049-8cd2-4580-8745-6679ac8d33f6%2COIDC&client_id=sample.client-id";

    @BeforeTest
    public void init() {

        uaePassAuthenticator = new UAEPassAuthenticator();
        authenticatorProperties = new HashMap<>();
        authenticatorProperties.put("callbackUrl", "http://localhost:8080/playground2/oauth2client");
        authenticatorProperties.put("commonAuthQueryParams", "scope=openid&state=OIDC&loginType=basic");
        authenticatorProperties.put("client_id", "sandbox_stage");
        authenticatorProperties.put("ClientSecret", "sandbox_stage");
        authenticatorProperties.put("UAEPassSTGUserInfoEndpoint", "https://stg-id.uaepass.ae/idshub/userinfo");
        authenticatorProperties.put("UAEPassSTGTokenEndpoint", "https://stg-id.uaepass.ae/idshub/token");
        authenticatorProperties.put("UAEPassSTGAuthzEndpoint", "https://stg-id.uaepass.ae/idshub/authorize");
        authenticatorProperties.put("UAEPassSTGLogoutEndpoint", "https://stg-id.uaepass.ae/idshub/logout");
        authenticatorProperties.put("UAEPassPRODUserInfoEndpoint", "https://id.uaepass.ae/idshub/userinfo");
        authenticatorProperties.put("UAEPassPRODTokenEndpoint", "https://id.uaepass.ae/idshub/token");
        authenticatorProperties.put("UAEPassPRODAuthzEndpoint", "https://id.uaepass.ae/idshub/authorize");
        authenticatorProperties.put("UAEPassPRODLogoutEndpoint", "https://id.uaepass.ae/idshub/logout");
        authenticatorProperties.put("UAEPassEnvironment", "staging");
        authenticatorProperties.put("scope", "urn:safelayer:tws:policies:authentication:level:low openid");
        authenticatorProperties.put("acr_values", "urn:safelayer:tws:policies:authentication:level:mobile");
        authenticatorProperties.put("language", "english");
        authenticatorProperties.put("redirect_uri", "https://stg-id.uaepass.ae/idshub/logout");
        authenticatorProperties.put("state", "O569jh-vbrty765-792PMLDR-NH591BV,OIDC");
        authenticatorProperties.put("IsLogoutEnable", "true");
        authenticatorProperties.put("IsStagingEnv", "true");

        mockAuthConfig = new AuthenticatorConfig();
    }

    @Test
    public void testClaimMappingWithNullValues() {

        Map<ClaimMapping, String> claims = new HashMap<>();
        Map<String, Object> entries = new HashMap<>();
        entries.put("zoneinfo", "GMT");
        entries.put("email", "test123@test.de");
        entries.put("phone_number", null);

        for (Map.Entry<String, Object> entry : entries.entrySet()) {
            uaePassAuthenticator.buildClaimMappings(claims, entry, null);
            assertNotNull(claims.get(
                            ClaimMapping.build(entry.getKey(), entry.getKey(), null, false)),
                    "Claim value is null.");
        }
    }

    @Test(dataProvider = "requestDataHandler")
    public void testCanHandle(String grantType, String state, String loginType, String expectedCanHandler,
                              String msgCanHandler) {

        when(mockServletRequest.getParameter("code")).thenReturn(grantType);
        when(mockServletRequest.getParameter("state")).thenReturn(state);
        when(mockServletRequest.getParameter("OIDC")).thenReturn(loginType);

        assertEquals(uaePassAuthenticator.canHandle(mockServletRequest), Boolean.parseBoolean(expectedCanHandler),
                msgCanHandler);
    }

    @Test
    public void testGetFriendlyName() {

        assertEquals(uaePassAuthenticator.getFriendlyName(), "UAEPass",
                "Invalid Friendly name for authenticator");
    }

    @Test
    public void testGetName() {

        assertEquals(uaePassAuthenticator.getName(), "UAEPassAuthenticator",
                "Invalid name for authenticator");
    }

    @Test
    public void testGetClaimDialectURI() {

        assertEquals(uaePassAuthenticator.getClaimDialectURI(), "http://wso2.org/oidc/claim",
                "Invalid claim dialect URI");
    }

    @DataProvider(name = "seperator")
    public Object[][] getSeperator() {

        return new String[][]{
                {","},
                {",,,"}
        };
    }

    @DataProvider(name = "requestDataHandler")
    public Object[][] getRequestStatus() {

        return new String[][]{
                {"code", "active,OIDC", "BASIC", "true", "Invalid can handle response for the request" },
                {null, "active,OIDC", null, "true", "Invalid can handle response for the request" },
                {null, null, null, "false", "Invalid can handle response for the request" }
        };
    }

    @DataProvider(name = "commonAuthParamProvider")
    public Object[][] getCommonAuthParams() {

        return new String[][]{
                {"scope=openid&state=OIDC&loginType=basic&redirect_uri=https://localhost:9443/commonauth",
                        "https://localhost:9443/commonauth", "The redirect URI is invalid"},
                {"state=OIDC&loginType=basic&redirect_uri=https://localhost:9443/commonauth",
                        "https://localhost:9443/commonauth", "The redirect URI is invalid"},
                {"state=OIDC&loginType=basic", "https://localhost:9443/commonauth", "The redirect URI is invalid"},
                {"login_hint=$authparam{username}", "https://localhost:9443/commonauth",
                        "The redirect URI is invalid"},
                {"login_hint=$authparam{username}&domain=$authparam{fidp}", "https://localhost:9443/commonauth",
                        "The redirect URI is invalid"}
        };
    }

    @DataProvider(name = "logoutProvider")
    public Object[][] getLogoutParams() {

        return new String[][]{
                {"https://localhost:9443/commonauth"},
                {null}
        };
    }

    @Test
    private void mockAuthenticationRequestContext(AuthenticationContext mockAuthenticationContext) {

        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        paramValueMap = new HashMap<>();
        when(mockAuthenticationContext.getProperty("oidc:param.map")).thenReturn(paramValueMap);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("");
    }

    private void setupTest() throws Exception {

        mockStatic(OAuthAuthzResponse.class);
        when(OAuthAuthzResponse.oauthCodeAuthzResponse(mockServletRequest)).thenReturn(mockOAuthzResponse);
        when(mockServletRequest.getParameter("domain")).thenReturn("carbon.super");
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockOAuthzResponse.getCode()).thenReturn("200");
        when(mockAuthenticationContext.getProperty("access_token")).thenReturn(accessToken);
        when(mockAuthenticationContext.getProperty("id_token")).thenReturn(idToken);
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        mockStatic(UAEPassDataHolder.class);
        when(UAEPassDataHolder.getInstance()).thenReturn(openIDConnectAuthenticatorDataHolder);
        when(openIDConnectAuthenticatorDataHolder.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManger);
        when(mockTenantManger.getTenantId(anyString())).thenReturn(TENANT_ID);

        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
        when(mockRealmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR))
                .thenReturn(",");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL("", false, false)).
                thenReturn("https://localhost:9443");

        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addParameter(anyString(), anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenReturn(serviceURL);
    }

    @Test
    public void testProcessAuthenticationResponse() throws Exception {

        setupTest();
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.anyObject()))
                .thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        uaePassAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);
        assertEquals(mockOAuthClientResponse.getParam("access_token"),
                accessToken, "Invalid access token in the authentication context.");
        assertEquals(mockOAuthClientResponse.getParam("id_token"),
                idToken, "Invalid id token in the authentication context.");
    }

    @Test
    public void testPassProcessAuthenticationWithParamValue() throws Exception {

        setupTest();
        authenticatorProperties.put("callbackUrl", "http://localhost:8080/playground2/oauth2client");
        Map<String, String> paramMap = new HashMap<>();
        paramMap.put("redirect_uri", "http:/localhost:9443/oauth2/redirect");
        when(mockAuthenticationContext.getProperty("oidc:param.map")).thenReturn(paramMap);
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.anyObject()))
                .thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        uaePassAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);
    }

    @Test
    public void testInitiateAuthenticationRequestNullProperties() throws AuthenticationFailedException {

        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(null);
        assertThrows(AuthenticationFailedException.class, () -> uaePassAuthenticator.initiateAuthenticationRequest
                (mockServletRequest, mockServletResponse,
                        mockAuthenticationContext));
    }

    @Test
    public void testPassProcessAuthenticationWithBlankCallBack() throws Exception {

        setupTest();
        authenticatorProperties.put("callbackUrl", "https://localhost:9443/commonauth");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true)).
                thenReturn("http:/localhost:9443/oauth2/callback");
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.anyObject())).thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        uaePassAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);
    }

    @Test
    public void testGetOauthResponseWithoutExceptions() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException {

        when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(mockOAuthJSONAccessTokenResponse);
        assertNotNull(uaePassAuthenticator.getOAuthResponse(mockOAuthClient, mockOAuthClientRequest));
    }

    @Test(expectedExceptions = UAEPassAuthnFailedException.class)
    public void testGetOauthResponseWithExceptions() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException {

        OAuthClientRequest oAuthClientRequest = mock(OAuthClientRequest.class);
        OAuthClient oAuthClient = mock(OAuthClient.class);
        when(oAuthClient.accessToken(oAuthClientRequest)).thenThrow(OAuthSystemException.class);
        uaePassAuthenticator.getOAuthResponse(oAuthClient, oAuthClientRequest);
    }

    @Test(expectedExceptions = UAEPassAuthnFailedException.class)
    public void testGetOauthResponseWithOAuthProblemExceptions() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException {

        OAuthClientRequest oAuthClientRequest = mock(OAuthClientRequest.class);
        OAuthClient oAuthClient = mock(OAuthClient.class);
        when(oAuthClient.accessToken(oAuthClientRequest)).thenThrow(OAuthProblemException.class);
        uaePassAuthenticator.getOAuthResponse(oAuthClient, oAuthClientRequest);
    }

    @Test
    private void setParametersForOAuthClientResponse(OAuthClientResponse mockOAuthClientResponse, String accessToken,
                                                     String idToken) {

        when(mockOAuthClientResponse.getParam("access_token")).thenReturn(accessToken);
        when(mockOAuthClientResponse.getParam("id_token")).thenReturn(idToken);
    }

    @Test(dataProvider = "commonAuthParamProvider")
    public void testInitiateAuthenticationRequest(String authParam, String expectedValue,
                                                  String errorMsg) throws Exception {

        setupTest();
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockServletResponse.encodeRedirectURL("https%3A%2F%2Flocalhost%3A9443%2Fcommonauth"))
                .thenReturn("https://localhost:9443/redirect");
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("ContextIdentifier");
        when(mockServletRequest.getParameter("domain")).thenReturn("carbon_super");
        authenticatorProperties.put("commonAuthQueryParams", authParam);
        when(mockUaePassAuthenticator.getRuntimeParams(mockAuthenticationContext)).
                thenReturn(authenticatorProperties);
        when(mockServletRequest.getParameter("scope=openid&state=OIDC&loginType=basic&redirect_uri" +
                "=https://localhost:9443/commonauth")).thenReturn(authParam);
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        uaePassAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
    }

    @DataProvider (name = "stateProviders")
    public Object[][] getStateProviders() {

        return new String[][] {
                { "O569jh-vbrty765-792PMLDR-NH591BV,OIDC", "O569jh-vbrty765-792PMLDR-NH591BV" },
                { "OIDC", "OIDC" },
                { null , null }
        };
    }

    @Test(dataProvider = "stateProviders")
    public void testGetContextIdentifier(String actualState, String expectedState) {

        when(mockServletRequest.getParameter("state")).thenReturn(actualState);
        assertEquals(uaePassAuthenticator.getContextIdentifier(mockServletRequest), expectedState);
    }

    @Test(dataProvider = "seperator")
    public void testBuildClaimMappings(String separator) throws Exception {

        Map<ClaimMapping, String> claims = new HashMap<>();
        Map<String, Object> entries = new HashMap<>();
        entries.put("scope", new Object());

        for (Map.Entry<String, Object> entry : entries.entrySet()) {
            uaePassAuthenticator.buildClaimMappings(claims, entry, separator);
            assertTrue(!claims.isEmpty(), "Claims[] is empty.");
        }
        entries = new HashMap<>();
        entries.put("scope", "[    \n" +
                "    {\"name\":\"Ram\", \"email\":\"example1@gmail.com\", \"age\":23},    \n" +
                "    {\"name\":\"Shyam\", \"email\":\"example2@gmail.com\", \"age\":28},  \n" +
                "]");
        for (Map.Entry<String, Object> entry : entries.entrySet()) {
            uaePassAuthenticator.buildClaimMappings(claims, entry, separator);
            assertTrue(!claims.isEmpty(), "Claims[] is empty.");
        }
    }

    @Test(dataProvider = "logoutProvider")
    public void testInitiateLogoutRequest(String postLogoutRedirectUri) throws Exception {

        setupTest();
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("ContextIdentifier");
        when(mockServletRequest.getParameter("redirect_uri")).thenReturn(postLogoutRedirectUri);
        uaePassAuthenticator.initiateLogoutRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
    }

    @Test
    public void testGetAuthenticatedUserId() throws AuthenticationFailedException {

        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put("sub", "5e142ae1-eaa5-45a5-a3c3-cdb6fe46d5cd");
        assertEquals(uaePassAuthenticator.getAuthenticatedUserId(idTokenClaims),
                "5e142ae1-eaa5-45a5-a3c3-cdb6fe46d5cd");
    }

    @Test
    public void testGetConfigurationProperties() {

        Property property = new Property();
        property.setValue("value");
        property.setName("name");
        property.setConfidential(false);
        property.setDefaultValue("defaultValue");
        property.setDisplayName("displayName");
        property.setRequired(false);
        property.setDescription("description");
        property.setType("type");
        property.setDisplayOrder(0);
        property.setAdvanced(false);
        property.setRegex("regex");
        property.setOptions(new String[]{"options"});

        SubProperty subProperty = new SubProperty();
        subProperty.setValue("value");
        subProperty.setName("name");
        property.setSubProperties(new SubProperty[]{subProperty});
        final List<Property> expectedResult = Arrays.asList(property);

        final List<Property> result = uaePassAuthenticator.getConfigurationProperties();

        Assert.assertNotEquals(expectedResult, result);
    }

    @Test
    public void testCanHandleForNativeSDKBasedFederation() {

        when(mockServletRequest.getParameter(UAEPassAuthenticatorConstants.ACCESS_TOKEN_PARAM))
                .thenReturn(accessToken);
        when(mockServletRequest.getParameter(UAEPassAuthenticatorConstants.ID_TOKEN_PARAM)).thenReturn(idToken);
        when(mockServletRequest.getParameter(UAEPassAuthenticatorConstants.SESSION_DATA_KEY_PARAM))
                .thenReturn(SESSION_DATA_KEY);
        when(mockServletRequest.getAttribute(FrameworkConstants.IS_API_BASED_AUTH_FLOW)).thenReturn(true);

        Assert.assertTrue(uaePassAuthenticator.canHandle(mockServletRequest));
        Assert.assertEquals(uaePassAuthenticator.getContextIdentifier(mockServletRequest), SESSION_DATA_KEY);
    }

    @Test
    public void testGetI18nKey() {

        String i18nKey = uaePassAuthenticator.getI18nKey();
        Assert.assertEquals(i18nKey, UAEPassAuthenticatorConstants.AUTHENTICATOR_I18N_KEY);
    }

    @Test
    public void testPassProcessAuthenticationResponseWithNativeSDKBaseFederation() throws Exception {

        setupTest();
        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("true");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(mockServletRequest.getParameter(UAEPassAuthenticatorConstants.ID_TOKEN_PARAM))
                .thenReturn(idToken);
        when(mockServletRequest.getParameter(UAEPassAuthenticatorConstants.ACCESS_TOKEN_PARAM))
                .thenReturn(accessToken);

        mockStatic(OIDCTokenValidationUtil.class);
        doNothing().when(OIDCTokenValidationUtil.class, "validateIssuerClaim", Mockito.any((JWTClaimsSet.class)));
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(SUPER_TENANT);
        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getIdPByMetadataProperty(
                Mockito.eq(IdentityApplicationConstants.IDP_ISSUER_NAME), anyString(), Mockito.eq(SUPER_TENANT),
                Mockito.eq(false))).thenReturn(identityProvider);
        doNothing().when(OIDCTokenValidationUtil.class, "validateSignature", Mockito.any(SignedJWT.class),
                Mockito.any(IdentityProvider.class));

        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        uaePassAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);

        assertEquals(mockAuthenticationContext.getProperty(UAEPassAuthenticatorConstants.UAE.ACCESS_TOKEN),
                accessToken, "Invalid access token in the authentication context.");

        assertEquals(mockAuthenticationContext.getProperty(UAEPassAuthenticatorConstants.UAE.ID_TOKEN), idToken,
                "Invalid Id token in the authentication context.");
    }

    @Test
    public void testGetAuthInitiationDataForNativeSDKBasedFederation() {

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("true");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).
                thenReturn(UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_NAME);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        authenticatorProperties.put(UAEPassAuthenticatorConstants.UAE.CLIENT_ID, CLIENT_ID);
        Optional<AuthenticatorData> authenticatorData = uaePassAuthenticator.getAuthInitiationData
                (mockAuthenticationContext);

        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        Assert.assertEquals(authenticatorDataObj.getName(),
                UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_NAME);
        Assert.assertEquals(authenticatorDataObj.getI18nKey(), UAEPassAuthenticatorConstants.AUTHENTICATOR_I18N_KEY);
        Assert.assertEquals(authenticatorDataObj.getDisplayName(),
                UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_FRIENDLY_NAME);
        Assert.assertEquals(authenticatorDataObj.getRequiredParams().size(),
                2);
        Assert.assertEquals(authenticatorDataObj.getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
        Assert.assertTrue(authenticatorDataObj.getRequiredParams()
                .contains(UAEPassAuthenticatorConstants.ACCESS_TOKEN_PARAM));
        Assert.assertTrue(authenticatorDataObj.getRequiredParams()
                .contains(UAEPassAuthenticatorConstants.ID_TOKEN_PARAM));
        Assert.assertEquals(authenticatorDataObj.getAdditionalData()
                .getAdditionalAuthenticationParams().get(UAEPassAuthenticatorConstants.CLIENT_ID_PARAM), CLIENT_ID);
    }

    @Test
    public void testGetAuthInitiationData() {

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName())
                .thenReturn(UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_NAME);
        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);
        when(mockAuthenticationContext.getProperty(
                UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_NAME +
                        UAEPassAuthenticatorConstants.REDIRECT_URL_SUFFIX))
                .thenReturn(REDIRECT_URL);
        Optional<AuthenticatorData> authenticatorData = uaePassAuthenticator.getAuthInitiationData
                (mockAuthenticationContext);

        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        Assert.assertEquals(authenticatorDataObj.getName(),
                UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_NAME);
        Assert.assertEquals(authenticatorDataObj.getI18nKey(), UAEPassAuthenticatorConstants.AUTHENTICATOR_I18N_KEY);
        Assert.assertEquals(authenticatorDataObj.getDisplayName(),
                UAEPassAuthenticatorConstants.UAE.FEDERATED_IDP_COMPONENT_FRIENDLY_NAME);
        Assert.assertEquals(authenticatorDataObj.getRequiredParams().size(),
                2);
        Assert.assertEquals(authenticatorDataObj.getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
        Assert.assertTrue(authenticatorDataObj.getRequiredParams()
                .contains(UAEPassAuthenticatorConstants.UAE.OAUTH2_GRANT_TYPE_CODE));
        Assert.assertTrue(authenticatorDataObj.getRequiredParams()
                .contains(UAEPassAuthenticatorConstants.UAE.OAUTH2_PARAM_STATE));
        Assert.assertEquals(authenticatorDataObj.getAdditionalData().getRedirectUrl(), REDIRECT_URL);
    }
}
