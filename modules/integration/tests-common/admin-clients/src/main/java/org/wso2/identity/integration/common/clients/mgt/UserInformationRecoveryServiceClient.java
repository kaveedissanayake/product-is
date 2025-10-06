/*
*  Copyright (c)  WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.identity.integration.common.clients.mgt;

import java.rmi.RemoteException;

import org.apache.axis2.AxisFault;
import org.wso2.carbon.captcha.mgt.beans.xsd.CaptchaInfoBean;
import org.wso2.carbon.identity.mgt.stub.dto.UserIdentityClaimDTO;
import org.wso2.carbon.identity.mgt.stub.dto.ChallengeQuestionDTO;
import org.wso2.carbon.identity.mgt.stub.dto.UserChallengesDTO;
import org.wso2.carbon.identity.mgt.stub.dto.ChallengeQuestionIdsDTO;
import org.wso2.carbon.identity.mgt.stub.beans.VerificationBean;
import org.wso2.carbon.identity.mgt.stub.UserInformationRecoveryServiceIdentityExceptionException;
import org.wso2.carbon.identity.mgt.stub.UserInformationRecoveryServiceIdentityMgtServiceExceptionException;
import org.wso2.carbon.identity.mgt.stub.UserInformationRecoveryServiceStub;
import org.wso2.identity.integration.common.clients.AuthenticateStub;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class UserInformationRecoveryServiceClient {

    private static final Log log = LogFactory.getLog(UserInformationRecoveryServiceClient.class);

	private UserInformationRecoveryServiceStub infoRecoveryStub;
    private final String serviceName = "UserInformationRecoveryService";
	
    public UserInformationRecoveryServiceClient(String backendURL, String sessionCookie)
            throws AxisFault {
        String endPoint = backendURL + serviceName;
        infoRecoveryStub = new UserInformationRecoveryServiceStub(endPoint);
        AuthenticateStub.authenticateStub(sessionCookie, infoRecoveryStub);
    }

    public UserInformationRecoveryServiceClient(String backendURL, String userName, String password)
            throws AxisFault {
        String endPoint = backendURL + serviceName;
        infoRecoveryStub = new UserInformationRecoveryServiceStub(endPoint);
        AuthenticateStub.authenticateStub(userName, password, infoRecoveryStub);
    }
    
	public CaptchaInfoBean getCaptcha() throws RemoteException {
		CaptchaInfoBean bean = null;
		try {
			bean = infoRecoveryStub.getCaptcha();
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error getting captcha", e);
		}
		return bean;
	}
    
    public VerificationBean verifyUser(String username, CaptchaInfoBean captcha) throws RemoteException {
    	VerificationBean bean = null;
    	try {
    		bean = infoRecoveryStub.verifyUser(username, captcha);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error verifying user", e);
		}
    	return bean;
    }
    
    public VerificationBean sendRecoveryNotification(String username, String key, String notificationType) throws RemoteException {
    	VerificationBean bean = null;
    	try {
    		bean = infoRecoveryStub.sendRecoveryNotification(username, key, notificationType);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error sending recovery notification", e);
		}
    	return bean;
    }
    
    public VerificationBean verifyConfirmationCode(String username, String code,
			CaptchaInfoBean captcha) throws RemoteException {
    	VerificationBean bean = null;
    	try {
    		bean = infoRecoveryStub.verifyConfirmationCode(username, code, captcha);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error verifying confirmation code", e);
		}
    	return bean;
    }
    
    public VerificationBean updatePassword(String username, String confirmationCode,
			String newPassword) throws RemoteException {
    	VerificationBean bean = null;
    	try {
    		bean = infoRecoveryStub.updatePassword(username, confirmationCode, newPassword);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error updating password", e);
		}
    	return bean;
    }
    
    public ChallengeQuestionIdsDTO getUserChallengeQuestionIds(String username, String confirmation) throws RemoteException {
    	ChallengeQuestionIdsDTO bean = null;
    	try {
    		bean = infoRecoveryStub.getUserChallengeQuestionIds(username, confirmation);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error getting user challenge question ids", e);
		}
    	return bean;
    }
    
    public UserChallengesDTO getUserChallengeQuestion(String userName, String confirmation,
			String questionId) throws RemoteException {
    	UserChallengesDTO bean = null;
    	try {
    		bean = infoRecoveryStub.getUserChallengeQuestion(userName, confirmation, questionId);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error getting user challenge question", e);
		}
    	return bean;
    }
    
    public VerificationBean verifyUserChallengeAnswer(String userName, String confirmation,
			String questionId, String answer) throws RemoteException {
    	VerificationBean bean = null;
    	try {
			bean = infoRecoveryStub.verifyUserChallengeAnswer(userName, confirmation, questionId, answer);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error verifying user challenge answer", e);
		}
    	return bean;
    }
    
    public ChallengeQuestionDTO[] getAllChallengeQuestions() throws RemoteException {
    	ChallengeQuestionDTO[] questions = null;
    	try {
			questions = infoRecoveryStub.getAllChallengeQuestions();
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error getting all challenge questions", e);
		}
    	return questions;
    }
    
    public UserIdentityClaimDTO[] getUserIdentitySupportedClaims(String dialect) throws RemoteException {
    	UserIdentityClaimDTO[] claims = null;
    	try {
			claims = infoRecoveryStub.getUserIdentitySupportedClaims(dialect);
        } catch (UserInformationRecoveryServiceIdentityExceptionException e) {
            log.error("Error getting user identity supported claims", e);
		}
    	return claims;
    }
    
    public VerificationBean verifyAccount(UserIdentityClaimDTO[] claims, CaptchaInfoBean captcha,
			String tenantDomain) throws RemoteException {
    	VerificationBean bean = null;
    	try {
			bean = infoRecoveryStub.verifyAccount(claims, captcha, tenantDomain);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error verifying account", e);
		}
    	return bean;
    }
    
    public VerificationBean registerUser(String userName, String password,
			UserIdentityClaimDTO[] claims, String profileName, String tenantDomain) throws RemoteException {
    	VerificationBean bean = null;
    	try {
			bean = infoRecoveryStub.registerUser(userName, password, claims, profileName, tenantDomain);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error registering user", e);
		}
    	return bean;
    }
    
    public VerificationBean confirmUserSelfRegistration(String username, String code,
			CaptchaInfoBean captcha, String tenantDomain) throws RemoteException {
    	VerificationBean bean = null;
    	try {
			bean = infoRecoveryStub.confirmUserSelfRegistration(username, code, captcha, tenantDomain);
        } catch (UserInformationRecoveryServiceIdentityMgtServiceExceptionException e) {
            log.error("Error confirming user self registration", e);
		}
    	return bean;
    }
}
	