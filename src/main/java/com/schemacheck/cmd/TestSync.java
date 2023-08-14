///*
// * IdMUnit - Automated Testing Framework for Identity Management Solutions
// * Copyright (c) 2005-2023 TriVir, LLC
// *
// * This program is licensed under the terms of the GNU General Public License
// * Version 2 (the "License") as published by the Free Software Foundation, and
// * the TriVir Licensing Policies (the "License Policies").  A copy of the License
// * and the Policies were distributed with this program.
// *
// * The License is available at:
// * http://www.gnu.org/copyleft/gpl.html
// *
// * The Policies are available at:
// * http://www.idmunit.org/licensing/index.html
// *
// * Unless required by applicable law or agreed to in writing, this program is
// * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// * OF ANY KIND, either express or implied.  See the License and the Policies
// * for specific language governing the use of this program.
// *
// * www.TriVir.com
// * TriVir LLC
// * 13890 Braddock Road
// * Suite 310
// * Centreville, Virginia 20121
// *
// */
//
//package com.schemacheck.cmd;
//
//import com.schemacheck.model.IdmUnitTest;
//import com.schemacheck.util.PicoCliValidation;
//import org.fusesource.jansi.AnsiConsole;
//import picocli.CommandLine;
//
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.PrintWriter;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.nio.file.Paths;
//import java.util.*;
//import java.util.stream.Collectors;
//import java.util.stream.Stream;
//
//import static picocli.CommandLine.*;
//
//@Command(name = "excel2json", description = "Converts IdMUnit Excel Workbooks into JSON.", mixinStandardHelpOptions = true, versionProvider = TestSync.ManifestVersionProvider.class, showDefaultValues = true)
//public class TestSync implements Runnable {
//    List<Connector> templateConnectors;
//    IdmUnitTest templateTest;
//    @Spec
//    Model.CommandSpec spec;
//
//    @Option(names = "--test-dir",
//            description = "The path to the directory containing the test workbooks.",
//            defaultValue = "test/org/idmunit")
//    Path testDirPath;
//
//    @Option(names = {"-t", "--template"},
//            description = "The title of the json file whose format will be standardized across the workbook",
//            defaultValue = "template")
//    Path templatePath;
//
//    @Option(names = "--log-file",
//            description = "The path to write the output errors and warnings to.",
//            defaultValue = "TestSync.log")
//    Path logFilePath;
//
//    List<Path> filePaths;
//
//    public static void main(String[] args) {
//        // To avoid warnings about Log42 not being in classpath
//        // See https://poi.apache.org/components/logging.html for more information (Specifically the Log4J SimpleLogger section)
//        Properties properties = System.getProperties();
//        properties.setProperty("log4j2.loggerContextFactory", "org.apache.logging.log4j.simple.SimpleLoggerContextFactory");
//
//        AnsiConsole.systemInstall();
//        CommandLine cmd = new CommandLine(new TestSync());
//        int exitCode = cmd.execute(args);
//        AnsiConsole.systemUninstall();
//        System.exit(exitCode);
//    }
//
//    @Override
//    public void run() {
//        PicoCliValidation.directoryExistsAndIsReadable(spec, testDirPath);
//        PicoCliValidation.fileExistsAndIsReadable(spec, templatePath);
//        PicoCliValidation.fileDoeNotExistOrAskOverwrite(spec, logFilePath);
//        try (PrintWriter logWriter = new PrintWriter(Files.newOutputStream(logFilePath))) {
//            try (InputStream templateStream = Files.newInputStream(templatePath)) {
//                templateTest = JsonUtils.getMapper().readValue(templateStream, IdmUnitTest.class);
//            } catch (IOException e) {
//                throw new RuntimeException("Failed to read from" + templatePath, e);
//            }
//            templateConnectors = templateTest.getConnectors();
//            List<IdmUnitTest> idmUnitTests = getFilePaths()
//                    .stream()
//                    .filter(jsonFile -> jsonFile.equals(templatePath) || !jsonFile.toString().contains("manifest"))
//                    .map(jsonFile -> {
//                        try (InputStream is = Files.newInputStream(jsonFile)) {
//                            return JsonUtils.getMapper().readValue(is, IdmUnitTest.class);
//                        } catch (IOException e) {
//                            throw new RuntimeException("Failed to read from " + jsonFile, e);
//                        }
//                    }).collect(Collectors.toList());
//            syncTests(logWriter, idmUnitTests);
//            for (IdmUnitTest test: idmUnitTests) {
//                Files.write(Paths.get(testDirPath.toAbsolutePath() + "\\" + test.getName() + ".json"), JsonUtils.getWriter().writeValueAsBytes(test));
//            }
//        } catch (IOException e) {
//            throw new RuntimeException("Failed to log output to " + logFilePath, e);
//        }
//    }
//
//    /**
//     * Adds missing test objects and removes objects not found in the given template
//     */
//    void syncTests(PrintWriter logWriter, List<IdmUnitTest> idmTests) {
//        for (IdmUnitTest idmUnitTest : idmTests) {
//            for (Connector connectorToRemove : getInvalidConnectors(idmUnitTest)) {
//                removeInvalidOperations(connectorToRemove, idmUnitTest, logWriter);
//            }
//            for (Connector connectorToRemove : getInvalidConnectors(idmUnitTest)) {
//                pruneOperations(idmUnitTest, logWriter, getInvalidAttributeNames(connectorToRemove).toArray(new String[0]));
//            }
//            for (Connector connector: templateConnectors) {
//                putConnector(idmUnitTest, connector);
//            }
//            idmUnitTest.getConnectors().removeAll(getInvalidConnectors(idmUnitTest));
//
//        }
//    }
//
//    /**
//     * Adds a connector to a test. if a connector by that name exists, does nothing
//     */
//    void putConnector(IdmUnitTest idmUnitTest, Connector templateConnector) {
//        List<String> presentConnectors = idmUnitTest.getConnectors().stream().map(Connector::getName).collect(Collectors.toList());
//        if (!presentConnectors.contains(templateConnector.getName())) {
//            idmUnitTest.getConnectors().add(templateConnector);
//        }
//    }
//
//    /**
//     * Adds all attributes from one connector to a test. Syncs existing connector's position if already found in test.
//     */
//    void syncTemplateAttributes(Connector templateConnector, IdmUnitTest idmUnitTest) {
//        if (!IdmTestUtils.getConnectorsNames(idmUnitTest).contains(templateConnector.getName())) {
//            idmUnitTest.getConnectors().add(templateConnector);
//            return;
//        }
//        Connector testConnector = IdmTestUtils.getConnector(idmUnitTest, templateConnector.getName());
//        for (ConnectorAttribute templateConnectorAttribute : templateConnector.getAttributes()) {
//            if (IdmTestUtils.getAttributeNames(testConnector).contains(templateConnectorAttribute.getName())) {
//                ConnectorAttribute testAttribute = IdmTestUtils.getAttribute(testConnector, templateConnectorAttribute.getName());
//                testAttribute.setGroupNum(templateConnectorAttribute.getGroupNum());
//                if (templateConnectorAttribute.getMeta().isEmpty()) {
//                    testAttribute.setMeta(new ArrayList<>());
//                } else {
//                    testAttribute.setMeta(templateConnectorAttribute.getMeta());
//                }
//            } else {
//                testConnector.getAttributes().add(templateConnectorAttribute);
//            }
//        }
//    }
//
//    /**
//     * Removes operations which target the given connector
//     */
//    void removeInvalidOperations(Connector testConnector, IdmUnitTest idmUnitTest, PrintWriter logWriter) {
//        List<Operation> operationsToRemove = idmUnitTest.getOperations().stream().filter(Objects::nonNull).filter(operation -> {
//            if (null != operation.getTarget()) {
//                return operation.getTarget().equalsIgnoreCase(testConnector.getName());
//            }
//            return false;
//        }).collect(Collectors.toList());
//        for (Operation operation : operationsToRemove) {
//            logWriter.printf("    |-- [WARN] Removing the %s connector from the %s test will remove the following data:\n\t%s\n",
//                    testConnector.getName(),
//                    idmUnitTest.getName(),
//                    IdmTestUtils.stringify(operation));
//        }
//        idmUnitTest.getOperations().removeAll(operationsToRemove);
//
//    }
//
//    /**
//     * Removes operational data which target invalid attributes
//     */
//    void pruneOperations(IdmUnitTest idmUnitTest, PrintWriter logWriter, String... badAttributes) {
//        for (Operation operation : idmUnitTest.getOperations()) {
//            List<OperationData> operationDataToRemove = new ArrayList<>();
//            for (OperationData operationData : operation.getData()) {
//                if (operationData != null) {
//                    if (Arrays.asList(badAttributes).contains(operationData.getAttribute())) {
//                        logWriter.printf("    |-- [WARN] Removing the %s attribute from the %s test will remove the following data:\n\t%s\n",
//                                operationData.getAttribute(),
//                                idmUnitTest.getName(),
//                                IdmTestUtils.stringify(operationData));
//                        operationDataToRemove.add(operationData);
//                    }
//                }
//            }
//            operation.getData().removeAll(operationDataToRemove);
//        }
//    }
//
//
//    List<Connector> getInvalidConnectors(IdmUnitTest idmUnitTest) {
//        return idmUnitTest.getConnectors()
//                .stream()
//                .filter(testConnector -> !templateConnectors.stream()
//                        .map(Connector::getName).collect(Collectors.toList())
//                        .contains(testConnector.getName()))
//                .collect(Collectors.toList());
//    }
//
//    /**
//     * Returns names of attributes which aren't included in any of the template's connectors.
//     */
//
//    List<String> getInvalidAttributeNames(Connector testConnector) {
//        return testConnector.getAttributes()
//                .stream().map(ConnectorAttribute::getName)
//                .filter(name -> templateConnectors.stream()
//                        .map(connector -> connector.getAttributes()
//                                .stream()
//                                .map(ConnectorAttribute::getName)
//                                .collect(Collectors.toList()))
//                        .anyMatch(templateConnectorName -> templateConnectorName.contains(name)))
//                .collect(Collectors.toList());
//    }
//
//
//    List<Path> getFilePaths() {
//        if (filePaths == null) {
//            try (Stream<Path> files = Files.walk(testDirPath, 1)) {
//                filePaths = files
//                        .filter(Files::isRegularFile)
//                        .filter(path -> path.toString().endsWith(".json"))
//                        .sorted(Comparator.reverseOrder())
//                        .collect(Collectors.toList());
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
//        }
//        return filePaths;
//    }
//
//    public static class ManifestVersionProvider implements IVersionProvider {
//        public String[] getVersion() {
//            return new String[]{TestSync.class.getPackage().getImplementationVersion()};
//        }
//    }
//}
