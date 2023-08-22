/*
 * IdMUnit - Automated Testing Framework for Identity Management Solutions
 * Copyright (c) 2005-2016 TriVir, LLC
 *
 * This program is licensed under the terms of the GNU General Public License
 * Version 2 (the "License") as published by the Free Software Foundation, and
 * the TriVir Licensing Policies (the "License Policies").  A copy of the License
 * and the Policies were distributed with this program.
 *
 * The License is available at:
 * http://www.gnu.org/copyleft/gpl.html
 *
 * The Policies are available at:
 * http://www.idmunit.org/licensing/index.html
 *
 * Unless required by applicable law or agreed to in writing, this program is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied.  See the License and the Policies
 * for specific language governing the use of this program.
 *
 * www.TriVir.com
 * TriVir LLC
 * 13890 Braddock Road
 * Suite 310
 * Centreville, Virginia 20121
 *
 */
package com.schemacheck.util.idmunit;


import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ConnectionConfigData {
    public static final String DISABLED = "disabled";
    private static final String XML_KEYSTORE = "keystore-path";
    private static final String XML_USER = "user";
    private static final String XML_PASSWORD = "password";
    private static final String XML_SERVER = "server";
    private Map<String, String> configParams = new HashMap<String, String>();
    private String name;
    private String type;
    private Map<String, String> dataSubstitutions;
    private List<InjectionConfigData> dataInjections;
    private Map<String, Alert> idmunitAlerts;
    private int multiplierRetry;
    private int multiplierWait;

    public ConnectionConfigData(String name, String type) {
        this.name = name;
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public String getParam(String paramName) {
        return configParams.get(paramName);
    }

    public void setParam(String paramName, String value) {
        configParams.put(paramName, value);
    }

    public Map<String, String> getParams() {
        return configParams;
    }

    public String getAdminCtx() {
        return configParams.get(XML_USER);
    }

    public String getAdminPwd() {
        return configParams.get(XML_PASSWORD);
    }

    public String getKeystorePath() {
        return configParams.get(XML_KEYSTORE);
    }

    public String getServerURL() {
        return configParams.get(XML_SERVER);
    }

    public Map<String, Alert> getIdmunitAlerts() {
        return idmunitAlerts;
    }

    public void setIdmunitAlerts(Map<String, Alert> idmunitAlerts) {
        this.idmunitAlerts = idmunitAlerts;
    }

    public List<InjectionConfigData> getDataInjections() {
        return dataInjections;
    }

    public void setDataInjections(List<InjectionConfigData> dataInjections) {
        this.dataInjections = dataInjections;
    }

    public boolean ifMultiplierRetry() {
        return multiplierRetry > 1;
    }

    public boolean ifMultiplierWait() {
        return multiplierWait > 1;
    }

    public int getMultiplierRetry() {
        return multiplierRetry;
    }

    public void setMultiplierRetry(int multiplierRetry) {
        this.multiplierRetry = multiplierRetry;
    }

    public int getMultiplierWait() {
        return multiplierWait;
    }

    public void setMultiplierWait(int multiplierWait) {
        this.multiplierWait = multiplierWait;
    }

    public Map<String, String> getSubstitutions() {
        return dataSubstitutions;
    }

    public void setSubstitutions(Map<String, String> substitutions) {
        this.dataSubstitutions = substitutions;
    }
}
