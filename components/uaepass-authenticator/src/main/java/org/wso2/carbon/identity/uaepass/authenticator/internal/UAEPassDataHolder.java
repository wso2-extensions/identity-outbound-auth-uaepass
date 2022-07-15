package org.wso2.carbon.identity.uaepass.authenticator.internal;

import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.user.core.service.RealmService;

public class UAEPassDataHolder {

    private static UAEPassDataHolder instance = new UAEPassDataHolder();

    private RealmService realmService;

    private ClaimMetadataManagementService claimMetadataManagementService;

    private UAEPassDataHolder() {

    }

    public static UAEPassDataHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public ClaimMetadataManagementService getClaimMetadataManagementService() {

        return claimMetadataManagementService;
    }

    public void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        this.claimMetadataManagementService = claimMetadataManagementService;
    }
}
