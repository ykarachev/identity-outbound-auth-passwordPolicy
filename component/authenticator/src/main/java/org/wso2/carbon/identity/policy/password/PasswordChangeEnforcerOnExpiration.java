/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.policy.password;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * this connector must only be present in an authentication step, where the user
 * is already identified by a previous step.
 */
public class PasswordChangeEnforcerOnExpiration extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(PasswordChangeEnforcerOnExpiration.class);

    private static final long serialVersionUID = 307784186695787941L;

    @Override
    public boolean canHandle(HttpServletRequest arg0) {
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(PasswordChangeEnforceConstants.STATE);
    }

    @Override
    public String getFriendlyName() {
        return PasswordChangeEnforceConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getName() {
        return PasswordChangeEnforceConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and doing complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        if (isNotBlank(request.getParameter(PasswordChangeEnforceConstants.CURRENT_PWD))
                && isNotBlank(request.getParameter(PasswordChangeEnforceConstants.NEW_PWD))
                && isNotBlank(request.getParameter(PasswordChangeEnforceConstants.NEW_PWD_CONFIRMATION))) {
            try {
                processAuthenticationResponse(request, response, context);
            } catch (Exception e) {
                context.setRetrying(true);
                context.setCurrentAuthenticator(getName());
                return initiateAuthRequest(request, response, context, e.getMessage());
            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        return initiateAuthRequest(request, response, context, null);
    }

    /**
     * this will prompt user to change the credentials only if the last password
     * changed time has gone beyond the pre-configured value.
     *
     * @param request  the request
     * @param response the response
     * @param context  the authentication context
     */
    protected AuthenticatorFlowStatus initiateAuthRequest(HttpServletRequest request, HttpServletResponse response,
                                                          AuthenticationContext context, String errorMessage) throws AuthenticationFailedException {
        // find the authenticated user.
        final AuthenticatedUser authenticatedUser = getUsername(context);
        final StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Authentication failed!. Cannot proceed further without identifying the user");
        }

        final String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        final String accountStatus = getAccountStatus(username);
        log.info("Account Status: " + accountStatus);
        if (isAccountStatusOpen(accountStatus)) {
            updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        if (isAccountStatusExpiredGrace(accountStatus) && stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
            // The password reset flow for local authenticator
            final String tenantDomain = authenticatedUser.getTenantDomain();
            final String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            final String fullyQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, tenantDomain);

            // the password has changed or the password changed time is not set.
            final String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL().replace("login.do", "pwd-reset.jsp");
            final String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier());
            try {
                String retryParam = "";
                if (context.isRetrying()) {
                    retryParam = "&authFailure=true&authFailureMsg=" + errorMessage;
                }
                String encodedUrl = (loginPage + ("?" + queryParams + "&username=" + fullyQualifiedUsername))
                        + "&authenticators=" + getName() + ":" + PasswordChangeEnforceConstants.AUTHENTICATOR_TYPE
                        + retryParam;
                log.info("Send redirect to " + encodedUrl);
                response.sendRedirect(encodedUrl);
                return AuthenticatorFlowStatus.INCOMPLETE;
            } catch (IOException e) {
                throw new AuthenticationFailedException(e.getMessage(), e);
            }
        }


        final String deniedPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL().replace("login.do", "pwd-denied.jsp");
        try {
            response.sendRedirect(deniedPage);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        context.setCurrentAuthenticator(getName());
        return AuthenticatorFlowStatus.INCOMPLETE;
    }


    private Connection getConnection() throws SQLException {
        final String jdbcUri = PasswordChangeUtils.getPasswordResetJdbcUri();
        final String jdbcUser = PasswordChangeUtils.getPasswordResetJdbcUser();
        final String jdbcPassword = PasswordChangeUtils.getPasswordResetJdbcPassword();

        final Properties properties = new Properties();
        properties.put("user", jdbcUser);
        properties.put("password", jdbcPassword);

        final String connectionPropertyName = PasswordChangeUtils.getPasswordResetPropertyName();
        final String connectionPropertyValue = PasswordChangeUtils.getPasswordResetPropertyValue();

        if (isNotBlank(connectionPropertyName) && isNotBlank(connectionPropertyValue)) {
            properties.put(connectionPropertyName, connectionPropertyValue);
        }

        return DriverManager.getConnection(jdbcUri, properties);
    }

    private String getAccountStatus(final String username) throws AuthenticationFailedException {
        final String query = PasswordChangeUtils.getPasswordResetAccountStatusQuery();

        try (final Connection connection = getConnection();
             final PreparedStatement statement = connection.prepareStatement(query)) {

            statement.setString(1, username);
            try (final ResultSet rs = statement.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(1).trim();
                }
            }
        } catch (SQLException e) {
            log.error(e);
            throw new AuthenticationFailedException(e.getMessage());
        }

        throw new AuthenticationFailedException("User '" + username + "' not found");
    }

    private boolean isAccountStatusOpen(String accountStatus) {
        return PasswordChangeUtils.getPasswordResetAccountStatusOpen().equalsIgnoreCase(accountStatus);
    }

    private boolean isAccountStatusExpiredGrace(String accountStatus) {
        return PasswordChangeUtils.getPasswordResetAccountStatusExpiredGrace().equalsIgnoreCase(accountStatus);
    }

    private void updatePassword(String username, String password) throws AuthenticationFailedException {
        final String call = PasswordChangeUtils.getPasswordResetCallAccountUpdate();
        log.info("Update password");
        try (final Connection connection = getConnection();
             final CallableStatement statement = connection.prepareCall(call)) {
            statement.setString(1, username);
            statement.setString(2, password);
            statement.execute();
        } catch (SQLException e) {
            log.error(e);
            throw new AuthenticationFailedException(e.getMessage());
        }
    }

    /**
     * Update the updateCredential.
     *
     * @param request  the request
     * @param response the response
     * @param context  the authentication context
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        AuthenticatedUser authenticatedUser = getUsername(context);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String tenantDomain = authenticatedUser.getTenantDomain();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm;
        UserStoreManager userStoreManager;
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user realm or user store manager", e);
        }

        final String currentPassword = request.getParameter(PasswordChangeEnforceConstants.CURRENT_PWD);
        final String newPassword = request.getParameter(PasswordChangeEnforceConstants.NEW_PWD);
        final String repeatPassword = request.getParameter(PasswordChangeEnforceConstants.NEW_PWD_CONFIRMATION);

        if (currentPassword == null || newPassword == null || repeatPassword == null) {
            throw new AuthenticationFailedException("All fields are required");
        }

        if (currentPassword.equals(newPassword)) {
            throw new AuthenticationFailedException("You cannot use your previous password as your new password");
        }

        if (!newPassword.equals(repeatPassword)) {
            throw new AuthenticationFailedException("The new password and confirmation password do not match");
        }

        try {
            validatePassword(userStoreManager, newPassword);

            userStoreManager.updateCredential(tenantAwareUsername, newPassword, currentPassword);
            updatePassword(username, newPassword);

            final String claimName = PasswordChangeUtils.getPasswordResetClaimName();
            final String encodedPassword = Base64.encodeBase64String(newPassword.getBytes());
            userStoreManager.setUserClaimValue(tenantAwareUsername, claimName, encodedPassword, null);

            if (log.isDebugEnabled()) {
                log.debug("Updated user credentials of " + tenantAwareUsername);
            }

        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            if (e.getMessage().contains("InvalidOperation")) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid operation. User store is read only.", e);
                }
                throw new AuthenticationFailedException("Invalid operation. User store is read only", e);
            }

            if (e.getMessage().contains("PasswordInvalid")) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid credentials. Cannot proceed with the password change.", e);
                }
                throw new AuthenticationFailedException("Invalid credentials. Cannot proceed with the password change.", e);
            }

            throw new AuthenticationFailedException("Error occurred while updating the password", e);
        }

        // authentication is now completed in this step. update the authenticated user information.
        updateAuthenticatedUserInStepConfig(context, authenticatedUser);
    }

    private void validatePassword(UserStoreManager userStoreManager, String newPassword) throws AuthenticationFailedException {
        final String regularExpression = userStoreManager.getRealmConfiguration().getUserStoreProperty("PasswordJavaRegEx");
        if (isEmpty(regularExpression)) {
            return;
        }

        if (isFormatCorrect(regularExpression, newPassword)) {
            return;
        }

        final String errorMsg = userStoreManager.getRealmConfiguration().getUserStoreProperty("PasswordJavaRegExViolationErrorMsg");
        if (isNotBlank(errorMsg)) {
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new AuthenticationFailedException(errorMsg);
        }

        if (log.isDebugEnabled()) {
            log.debug("New password doesn't meet the policy requirement. It must be in the following format, "
                            + regularExpression);
        }
        throw new AuthenticationFailedException("New password doesn't meet the policy requirement. It must be in the following format, "
                        + regularExpression);
    }

    private boolean isFormatCorrect(String regularExpression, String password) {
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(password);
        return m2.matches();
    }

    /**
     * Get the username from authentication context.
     *
     * @param context the authentication context
     */
    private AuthenticatedUser getUsername(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = null;
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedUser() != null) {
            authenticatedUser = stepConfig.getAuthenticatedUser();
        }

        return authenticatedUser;
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    private void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser) {
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            stepConfig.setAuthenticatedUser(authenticatedUser);
        }
        context.setSubject(authenticatedUser);
    }

}
