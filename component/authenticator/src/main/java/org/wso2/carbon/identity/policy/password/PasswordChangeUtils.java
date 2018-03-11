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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class PasswordChangeUtils {
    public static final String IDM_PROPERTIES_FILE = "identity-mgt.properties";
    public static final String PASSWORD_RESET_CLAIM_VALUE = "Authentication.Policy.Password.Reset.Claim.Value";
    public static final String PASSWORD_RESET_CLAIM = "Authentication.Policy.Password.Reset.Claim";
    public static final String PASSWORD_RESET_DEFAULT_CLAIM_VALUE = "KioqKioqKioq";
    public static final String PASSWORD_RESET_DEFAULT_CLAIM = "http://wso2.org/claims/externalid";
    public static final String PASSWORD_RESET_JDBC_URI = "Authentication.Policy.Password.Reset.Jdbc.Uri";
    public static final String PASSWORD_RESET_JDBC_DRIVER = "Authentication.Policy.Password.Reset.Jdbc.DriverClass";
    private static boolean driverRegistered;
    private static Properties properties = new Properties();

    private static final Log log = LogFactory.getLog(PasswordChangeUtils.class);

    static {
        loadProperties();
    }

    private PasswordChangeUtils() {
    }

    /**
     * loading the identity-mgt.properties file.
     */
    public static void loadProperties() {
        FileInputStream fileInputStream = null;
        String configPath = CarbonUtils.getCarbonConfigDirPath() + File.separator + "identity" + File.separator;
        try {
            configPath = configPath + IDM_PROPERTIES_FILE;
            fileInputStream = new FileInputStream(new File(configPath));
            properties.load(fileInputStream);
            registerDriver();
        } catch (FileNotFoundException e) {
            throw new RuntimeException("identity-mgt.properties file not found in " + configPath, e);
        } catch (IOException e) {
            throw new RuntimeException("identity-mgt.properties file reading error from " + configPath, e);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (Exception e) {
                    log.error("Error occurred while closing stream :" + e);
                }
            }
        }
    }

    public static String getPasswordResetClaimName() {
        String claimName = (String) properties.get(PASSWORD_RESET_CLAIM);
        if (claimName != null) {
            return claimName;
        }

        return PASSWORD_RESET_DEFAULT_CLAIM;
    }

    public static String getPasswordResetClaimValue() {
        String claimValue = (String) properties.get(PASSWORD_RESET_CLAIM_VALUE);
        if (claimValue != null) {
            return claimValue;
        }

        return PASSWORD_RESET_DEFAULT_CLAIM_VALUE;
    }

    public static String getPasswordResetJdbcUri() {
        String jdbcUri = (String) properties.get(PASSWORD_RESET_JDBC_URI);
        if (jdbcUri != null) {
            return jdbcUri;
        }
        return null;
    }

    private static void registerDriver() {
        if (driverRegistered) {
            return;
        }

        String jdbcUri = (String) properties.get(PASSWORD_RESET_JDBC_DRIVER);
        if (jdbcUri != null) {
            try {
                Class.forName(jdbcUri);
                driverRegistered = true;
            } catch (Exception e) {
                log.error("Error occurred while driver registration :", e);
            }
        }
    }


}