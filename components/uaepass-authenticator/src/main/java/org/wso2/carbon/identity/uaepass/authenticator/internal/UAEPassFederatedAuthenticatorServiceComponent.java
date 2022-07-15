/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.uaepass.authenticator.internal;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.uaepass.authenticator.UAEPassAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

@Component(name = "uae.pass.federated.authenticator", immediate = true)

public class UAEPassFederatedAuthenticatorServiceComponent {

    private static final Log LOG = LogFactory.getLog(UAEPassFederatedAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            UAEPassAuthenticator uaePassFederatedAuthenticator = new UAEPassAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), uaePassFederatedAuthenticator, null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("UAE Pass Federated Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            LOG.fatal(" Error while activating UAE Pass federated authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("UAE Pass federated Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Realm Service");
        }
        UAEPassDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("UnSetting the Realm Service");
        }
        UAEPassDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "claim.manager.listener.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimManagementService"
    )
    protected void setClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        UAEPassDataHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);
    }

    protected void unsetClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        UAEPassDataHolder.getInstance()
                .setClaimMetadataManagementService(null);
    }
}
