/*
 * IdMUnit - Automated Testing Framework for Identity Management Solutions
 * Copyright (c) 2005-2023 TriVir, LLC
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
package com.schemacheck.util;

import com.schemacheck.model.Connector;
import com.schemacheck.model.ConnectorAttribute;
import com.schemacheck.model.IdmUnitTest;
import com.schemacheck.model.Operation;
import com.schemacheck.model.OperationData;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class IdmTestUtils {
    public static ConnectorAttribute[] getAttributes(Connector connector, String attributeName) {
        return connector.getAttributes()
                .stream()
                .filter(connectorAttribute -> connectorAttribute.getName().equalsIgnoreCase(attributeName))
                .toArray(ConnectorAttribute[]::new);
    }


    public static List<String> getConnectorsNames(IdmUnitTest idmUnitTest) {
        return idmUnitTest.getConnectors()
                .stream()
                .map(Connector::getName)
                .collect(Collectors.toList());
    }

    public static Connector getConnector(IdmUnitTest idmUnitTest, String connectorName) {
        Optional<Connector> optionalConnector = idmUnitTest.getConnectors().stream()
                .filter(connector -> connector.getName().equalsIgnoreCase(connectorName))
                .findFirst();
        if (optionalConnector.isPresent()) {
            return optionalConnector.get();
        }
        throw new IllegalArgumentException(String.format("Bad name requested. Cannot find '%s' connector", connectorName));
    }

    public static List<String> getAttributeNames(Connector connector) {
        return connector.getAttributes()
                .stream()
                .map(ConnectorAttribute::getName)
                .collect(Collectors.toList());
    }

    public static String stringify(OperationData operationData) {
        return String.join("\n\t", new String[]{
            "\tattribute: " + operationData.getAttribute(),
            "value(s): <[" + String.join("]>, <[", operationData.getValue()) + "]>",
            "OperationData meta: <[" + String.join("]>, <[", operationData.getMeta()) + "]>",
        });
    }


    public static String stringify(Operation operation) {
        return String.join("\n\t", new String[]{
            "\tcomment: " + operation.getComment(),
            "operation: " + operation.getOperation(),
            "target: " + operation.getTarget(),
            "waitInterval: " + operation.getWaitInterval(),
            "retryCount: " + operation.getRetryCount(),
            "disabled: " + operation.getDisabled(),
            "failureExpected: " + operation.getFailureExpected(),
            "critical: " + operation.getCritical(),
            "repeatRange: " + operation.getRepeatRange(),
            "data: " + operation.getData().stream().map(IdmTestUtils::stringify).collect(Collectors.joining("\n\t")),
            "operation meta: " + String.join("\n\t", operation.getMeta())}
        );

    }

}
