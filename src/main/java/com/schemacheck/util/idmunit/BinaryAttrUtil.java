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

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Pattern;

public class BinaryAttrUtil {
    public static final String ATTR_PREFIX_BIN = "bin_";
    public static final String ATTR_PREFIX_B64 = "b64_";
    public static final String REGEX_NEWLINE = "\\r|\\n";
    public static final String JNDI_PROPERTY_LDAP_ATTRIBUTES_BINARY = "java.naming.ldap.attributes.binary";
    //doesn't return null
    private static File getFile(String pathOrUri) throws IdMUnitException {
        if (pathOrUri == null || pathOrUri.trim().isEmpty()) {
            throw new IllegalArgumentException("Param 'pathOrUri' is blank");
        }

        //file URIs do not support relative paths
        boolean isUri = pathOrUri.matches("^[a-zA-Z]+://.*");

        File file;
        if (isUri) {
            //URI
            try {
                file = new File(new URI(pathOrUri));
            } catch (URISyntaxException e) {
                throw new IdMUnitException(String.format("Invalid file URI: %s", pathOrUri), e);
            }
        } else {
            //path
            file = new File(pathOrUri);
        }

        return file;
    }

    //doesn't return null
    private static byte[] readFileAsBytes(File file) throws IdMUnitException {
        if (file == null) {
            throw new IllegalArgumentException("Param 'file' is null");
        }

        if (!file.exists()) {
            throw new IdMUnitException(String.format("File '%s' doesn't exist.", file.getAbsolutePath()));
        }
        InputStream inStream = null;
        try {
            inStream = new FileInputStream(file);
            long length = file.length();
            byte[] bytes = new byte[(int)length];

            inStream.read(bytes);
            inStream.close();

            return bytes;
        } catch (FileNotFoundException e) {
            throw new IdMUnitException(String.format("Unable to locate file '%s': %s", file.getAbsolutePath(), e.getMessage()), e);
        } catch (IOException e) {
            throw new IdMUnitException(String.format("Error reading file %s: %s", file.getAbsolutePath(), e.getMessage()), e);
        } finally {
            if (inStream != null) {
                try {
                    inStream.close();
                } catch (IOException e) {
                    //ignore
                }
            }
        }
    }

    //doesn't return null
    private static String readFileAsString(File file, Pattern omitLine) throws IdMUnitException {
        if (file == null) {
            throw new IllegalArgumentException("Param 'file' is null");
        }

        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(file));

            String line;
            StringBuilder stringBuilder = new StringBuilder();
            String ls = System.getProperty("line.separator");

            while ((line = reader.readLine()) != null) {
                if (omitLine == null || !omitLine.matcher(line).matches()) {
                    stringBuilder.append(line);
                    stringBuilder.append(ls);
                }
            }

            return stringBuilder.toString();
        } catch (FileNotFoundException e) {
            throw new IdMUnitException(String.format("Unable to locate file '%s': %s", file.getAbsolutePath(), e.getMessage()), e);
        } catch (IOException e) {
            throw new IdMUnitException(String.format("Error reading file %s: %s", file.getAbsolutePath(), e.getMessage()), e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    //ignore
                }
            }
        }
    }

    public static Collection<byte[]> getBinValues(Collection<String> values) throws IdMUnitException {
        if ((values == null) || values.isEmpty()) {
            //nothing to do
            return Collections.emptyList();
        }

        List<byte[]> byteList = new ArrayList<byte[]>(values.size());
        for (Iterator<String> i = values.iterator(); i.hasNext(); ) {
            String pathOrUri = i.next();
            File file = getFile(pathOrUri);
            byte[] bytes = readFileAsBytes(file);
            byteList.add(bytes);
        }

        return byteList;
    }

    public static Collection<String> getB64Values(Collection<String> values) throws IdMUnitException {
        if ((values == null) || values.isEmpty()) {
            //nothing to do
            return Collections.emptyList();
        }

        List<String> encodedList = new ArrayList<String>(values.size());
        for (Iterator<String> i = values.iterator(); i.hasNext(); ) {
            String value = i.next();
            File file = getFile(value);
            String encoded = "";
            if (file.exists()) {
                //read file contents, omitting comments
                Pattern pattern = Pattern.compile("^--.*");
                encoded = readFileAsString(file, pattern);
                if (encoded.isEmpty()) {
                    throw new IdMUnitException(String.format("File '%s' is empty", file.getAbsolutePath()));
                }
            } else {
                //assume Base64-encoded value
                encoded = value;
            }

            if (!encoded.isEmpty()) {
                encodedList.add(encoded);
            }
        }

        return encodedList;
    }

    //returned collection is a different object
    public static Collection<String> replaceAll(Collection<String> toReplace, String regex, String replacement) {
        if ((toReplace == null) || toReplace.isEmpty()) {
            //nothing to do
            return toReplace;
        }

        if ((regex == null) || regex.isEmpty()) {
            //nothing to do
            return toReplace;
        }

        if (replacement == null) {
            replacement = "";
        }

        List<String> replaced = new ArrayList<String>(toReplace.size());
        for (String original : toReplace) {
            replaced.add(original.replaceAll(regex, replacement));
        }

        return replaced;
    }

    public static byte[] toBytes(String b64Encoded) throws IdMUnitException {
        if ((b64Encoded == null) || b64Encoded.trim().isEmpty()) {
            return null;
        }

        Base64.Decoder codec = Base64.getDecoder();
        try {
            return codec.decode(b64Encoded);
        } catch (RuntimeException e) {
            throw new IdMUnitException(String.format("Invalid Base64-encoded string: '%s'", b64Encoded), e);
        }
    }

    public static Collection<String> toB64(Collection<byte[]> byteList) {
        Base64.Encoder codec = Base64.getEncoder();

        if ((byteList == null) || byteList.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> b64EncodedList = new ArrayList<String>(byteList.size());
        for (byte[] bytes : byteList) {
            b64EncodedList.add(codec.encodeToString(bytes));
        }

        return b64EncodedList;
    }

    public static Collection<byte[]> toBytes(Collection<String> b64EncodedList) throws IdMUnitException {

        if ((b64EncodedList == null) || b64EncodedList.isEmpty()) {
            return Collections.emptyList();
        }

        Base64.Decoder codec = Base64.getDecoder();
        String b64 = "";

        List<byte[]> byteList = new ArrayList<byte[]>(b64EncodedList.size());
        try {
            for (String encoded : b64EncodedList) {
                b64 = encoded;
                byte[] bytes = codec.decode(b64);
                byteList.add(bytes);
            }
        } catch (RuntimeException e) {
            throw new IdMUnitException(String.format("Invalid Base64-encoded string: '%s'", b64), e);
        }

        return byteList;
    }

    public static final String stripPrefix(String s, String prefix) {
        return s.substring(prefix.length());
    }

    // TODO: only pass in binary attributes and remove the prefix logic so the method is more modular
    // See https://docs.oracle.com/javase/7/docs/technotes/guides/jndi/spec/jndi/jndi.6.html
    public static void updateBinaryAttrsProperty(DirContext context, Collection<String> attrNames) {
        if ((attrNames == null) || attrNames.isEmpty()) {
            return;
        }

        Collection<String> newBinAttrNames = Collections.emptyList();
        for (String attrName : attrNames) {
            if (attrName.equalsIgnoreCase(LdapConnector.STR_DN)) {
                continue;
            }

            if (attrName.toLowerCase().startsWith(ATTR_PREFIX_BIN)) {
                attrName = stripPrefix(attrName, ATTR_PREFIX_BIN);
                if (newBinAttrNames.isEmpty()) {
                    newBinAttrNames = new ArrayList<String>(attrNames.size());
                }
                newBinAttrNames.add(attrName);
            } else if (attrName.toLowerCase().startsWith(ATTR_PREFIX_B64)) {
                attrName = stripPrefix(attrName, ATTR_PREFIX_B64);
                if (newBinAttrNames.isEmpty()) {
                    newBinAttrNames = new ArrayList<String>(attrNames.size());
                }
                newBinAttrNames.add(attrName);
            }
        }

        if (newBinAttrNames.isEmpty()) {
            return;
        }

        try {
            List<String> allBinAttrNames = new ArrayList<String>();

            Object objProperty = context.getEnvironment().get(JNDI_PROPERTY_LDAP_ATTRIBUTES_BINARY);
            if ((objProperty != null) && (objProperty instanceof String)) {
                String property = (String)objProperty;
                if (!property.trim().isEmpty()) {
                    allBinAttrNames.addAll(Arrays.asList(property.split("\\s*,\\s*")));
                }
            }

            boolean update = false;
            for (String newAttrName : newBinAttrNames) {
                if (!allBinAttrNames.contains(newAttrName)) {
                    allBinAttrNames.add(newAttrName);
                    update = true;
                }
            }

            if (update) {
                StringBuilder builder = new StringBuilder();
                for (String attrName : allBinAttrNames) {
                    builder.append(" ");
                    builder.append(attrName);
                }

                context.addToEnvironment(JNDI_PROPERTY_LDAP_ATTRIBUTES_BINARY, builder.toString().trim());
            }
        } catch (NamingException e) {
//            log.error(String.format("Unable to update JNDI context's '%s' property. Binary attribute data will not be returned as bytes. This will negatively impact operations on binary attributes.",
//                    JNDI_PROPERTY_LDAP_ATTRIBUTES_BINARY), e);
        }
    }
}
