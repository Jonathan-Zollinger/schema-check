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


import javax.naming.Binding;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.regex.Pattern;

// TODO: pre-process bin_ and b_64 attributes so the values are base64-encoded by the time they're passed to any of
//  the operations; that is, read and encode the contents of any file path or URI references in BasicConnector
public class LdapConnector extends BasicConnector {
    public static final String STR_DN = "dn";
    public static final String STR_SUCCESS = "...SUCCESS";
    public static final String STR_DXML_ASSOC = "DirXML-Associations";
    private static final String STR_NEW_DN = "newdn";
    private static final String STR_USER_PASSWORD = "userPassword";
    private static final String STR_USER_OLD_PASSWORD = "oldUserPassword";
    private static final String STR_USER_NEW_PASSWORD = "newUserPassword";
    private static final String STR_BASE_DN_DELIMITER = ",base=";
    private static final String STR_UNICODE_PASSWORD = "unicodePwd";
    private static final String IDMUNIT_EMPTY_VALUE = "[EMPTY]";
    protected String server;
    private TreeSet<String> operationalAttributes = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
    private boolean insensitive = false;
    private DirContext context;
    private Map<String, String> config; //Storing config for use in opValidatePassword.

    // No longer supporting the changing of a password along with a modify; as it can be ambiguous: We'd rather have the end user decide whether it's a change vs reset, despite available columns.
    private boolean allowPasswordResetOnModifyOp = true;

    public LdapConnector() {
        operationalAttributes.add("nsaccountlock");
        operationalAttributes.add("DirXML-State");
        operationalAttributes.add("pwdaccountlockedtime");
        operationalAttributes.add("members");
    }

    // TODO: Update handling of msExchUMPinChecksum attr so it's handled as a byte[] and use LdapConnectioHelper method
    //  instead
    private static TreeMap<String, Collection<String>> attributesToMap(Attributes attributes) throws NamingException {
        TreeMap<String, Collection<String>> attrs = new TreeMap<String, Collection<String>>(String.CASE_INSENSITIVE_ORDER);
        NamingEnumeration<? extends Attribute> i = null;
        try {
            for (i = attributes.getAll(); i.hasMore(); ) {
                Attribute attr = i.next();
                String attrName = attr.getID();
                List<String> attrValues = new LinkedList<String>();
                for (NamingEnumeration<?> j = attr.getAll(); j.hasMore(); ) {
                    Object value = j.next();
                    if ("msExchUMPinChecksum".equals(attrName)) {
                        //TODO: BUG? add this attr to the "java.naming.ldap.attributes.binary" env. property so it's returned
                        // as a byte[]? using String.getBytes() didn't work for other binary attributes
                        attrValues.add(Base64.getEncoder().encodeToString(((String)value).getBytes()));
                    } else if (value instanceof byte[]) {
                        attrValues.add(Base64.getEncoder().encodeToString((byte[])value));
                    } else if (value instanceof String) {
                        attrValues.add((String)value);
                    } else {
                        
                    }
                }
                attrs.put(attrName, attrValues);
            }
        } catch (NamingException e) {
            try {
                if (i != null) {
                    i.close();
                }
            } catch (NamingException namingException) { //TODO: talk to huston about error handling here. seems inconsequencial.
                
            }
            throw e;
        }

        return attrs;
    }

    private static String getDXMLAssocByDriverName(String driverDn, Collection<String> attr) {
        for (Iterator<String> i = attr.iterator(); i.hasNext(); ) {
            Object attrVal = i.next();
            if (attrVal != null) {
                if (attrVal instanceof String) {
                    String attrValStr = (String)attrVal;
                    if (attrValStr.toUpperCase().startsWith(driverDn.toUpperCase())) {
                        return attrValStr;
                    }
                }
            } else {
                
            }
        }
        return null;
    }

    private static byte[] getUnicodeBytes(String password) {
        //Replace the "unicdodePwd" attribute with a new value
        //Password must be both Unicode and a quoted string
        String newQuotedPassword = null;
        byte[] newUnicodePassword = null;
        try {
            newQuotedPassword = "\"" + password + "\"";
            newUnicodePassword = newQuotedPassword.getBytes("UTF-16LE");
        } catch (UnsupportedEncodingException uee) {
            throw new Error("UTF-16LE encoding not supported.");
        }
        return newUnicodePassword;
    }

    public void opAddAttr(Map<String, Collection<String>> dataRow) throws IdMUnitException {
        modifyObject(dataRow, DirContext.ADD_ATTRIBUTE);
    }

    public void opAddObject(Map<String, Collection<String>> dataRow) throws IdMUnitException {
        String dn = null;
        Attributes createAttrs = new BasicAttributes();
        // insert attributes from incoming map
        for (String attrName : dataRow.keySet()) {
            Collection<String> dataValue = dataRow.get(attrName);

            if (dataValue.size() == 0) {
                continue;
            }

            if (attrName.equalsIgnoreCase(STR_DN)) {
                dn = dataValue.iterator().next();
                
            } else if (attrName.equalsIgnoreCase(STR_UNICODE_PASSWORD)) {
                byte[] unicodePwdVal = getUnicodeBytes(dataValue.iterator().next());
                createAttrs.put(attrName, unicodePwdVal);
            } else if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_BIN)) {
                Collection<String> values = dataRow.get(attrName);
                attrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_BIN);
                Attribute attr = new BasicAttribute(attrName);

                Collection<byte[]> byteList = BinaryAttrUtil.getBinValues(values);
                for (byte[] bytes : byteList) {
                    attr.add(bytes);
                }

                createAttrs.put(attr);
            } else if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_B64)) {
                Collection<String> values = dataRow.get(attrName);
                attrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_B64);
                Attribute attr = new BasicAttribute(attrName);

                Collection<String> encodedList = BinaryAttrUtil.getB64Values(values);
                Collection<byte[]> byteList = BinaryAttrUtil.toBytes(encodedList);
                for (byte[] bytes : byteList) {
                    attr.add(bytes);
                }

                createAttrs.put(attr);
            } else {
                BasicAttribute multiValuedAttr = new BasicAttribute(attrName);
                for (Iterator<String> i = dataValue.iterator(); i.hasNext(); ) {
                    multiValuedAttr.add(i.next());
                }
                createAttrs.put(multiValuedAttr);
            }
        }

        if (dn == null) {
            throw new IdMUnitException("A Distinguished Name must be supplied in column '" + STR_DN + "'");
        }

        // logger.debug("Binding DN " + dn);
        try {
            DirContext tmpCtx = this.context.createSubcontext(dn, createAttrs);
            if (tmpCtx != null) {
                tmpCtx.close(); //this is necessary in order to keep the parent connection ctx clean enough to be pooled/managed as week references inside of the parent DirContext will prevent proper pooling
            }
            //  logger.debug(">>>" + dn + " created");
            
        } catch (NamingException e) {
            throw new IdMUnitException("Failed to create object: " + dn + " with error: " + e.getMessage(), e);
        }
    }

    public void opDeleteObject(Map<String, Collection<String>> data) throws IdMUnitException {
        String dn;
        try {
            dn = getTargetDn(data);
        } catch (IdMUnitException e) {
            //A wild-card search failed to find an entry, or the DN field in the spreadsheet is blank
            
            return; // Never fail when told to delete a DN that isn't there
        }

        try {
            context.lookup(dn);
            
            context.unbind(dn);
            
        } catch (NamingException e) {
            if (e instanceof NameNotFoundException) {
                return;
            } else {
                String errorMessage = e.getMessage().toUpperCase();
                if (errorMessage.indexOf("NO SUCH ENTRY") != -1 || errorMessage.indexOf("NO_OBJECT") != -1 || errorMessage.indexOf("OBJECT") != -1) {
                    return;
                } else {
                    throw new IdMUnitException("Deletion failure: Invalid DN: " + e.getMessage(), e);
                }
            }
        }
    }

    public void opMoveObject(Map<String, Collection<String>> data) throws IdMUnitException {
        String dn = ConnectorUtil.getSingleValue(data, STR_DN);
        if (dn == null) {
            throw new IdMUnitException("A Distinguished Name must be supplied in column '" + STR_DN + "'");
        }

        String newDn = ConnectorUtil.getSingleValue(data, STR_NEW_DN);
        if (newDn == null) {
            throw new IdMUnitException("A Distinguished Name must be supplied in column '" + STR_NEW_DN + "'");
        }

        
        try {
            context.rename(dn, newDn);
            
        } catch (NamingException e) {
            throw new IdMUnitException("Move/Rename failure: Error: " + e.getMessage(), e);
        }
    }

    public void opRenameObject(Map<String, Collection<String>> assertedAttrs) throws IdMUnitException {
        opMoveObject(assertedAttrs);
    }

    public void opValidateObject(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        doValidate(expectedAttrs, false);
        String passwordVal = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_PASSWORD);

        if (passwordVal == null) {
            //fallback to unicode password so the end user can use the same password attribute to set and
            // validate the password
            passwordVal = ConnectorUtil.getSingleValue(expectedAttrs, STR_UNICODE_PASSWORD);
        }

        if (passwordVal != null) {
            opValidatePassword(expectedAttrs);
        }
    }

    public void opClearAttr(Map<String, Collection<String>> data) throws IdMUnitException {
        String dn = getTargetDn(data);
        

        List<ModificationItem> mods = new ArrayList<ModificationItem>();
        for (String attrName : data.keySet()) {
            if (attrName.equalsIgnoreCase(STR_DN)) {
                continue;
            }

            for (String attrVal : data.get(attrName)) {
                if ("*".equals(attrVal) == false) {
                    throw new IdMUnitException("You must specify '*' as the attribute value for the clearAttr operation.");
                }
            }
            mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(attrName)));
        }

        if (mods.size() > 0) {
            try {
                context.modifyAttributes(dn, (ModificationItem[])mods.toArray(new ModificationItem[mods.size()]));
            } catch (NameNotFoundException e) {
                
                // TODO: send warning here?
            } catch (NamingException e) {
                if (e.getMessage().contains("16")) {
                    
                } else {
                    throw new IdMUnitException("Modification failure: Error: " + e.getMessage(), e);
                }
            }
        } else {
            
        }

        
    }

    public void opRemoveAttr(Map<String, Collection<String>> data) throws IdMUnitException {
        String dn = getTargetDn(data);
        

        TreeMap<String, Collection<String>> curAttrs;
        try {
            curAttrs = getAttributes(dn);
        } catch (IdMUnitException e) {
            
            return;
        }

        List<ModificationItem> mods = new ArrayList<ModificationItem>();
        for (String attrName : data.keySet()) {
            if (attrName.equalsIgnoreCase(STR_DN)) {
                continue;
            } else if (attrName.equals(STR_UNICODE_PASSWORD)) {
                byte[] unicodePwdVal = getUnicodeBytes(ConnectorUtil.getSingleValue(data, STR_UNICODE_PASSWORD));
                mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(attrName, unicodePwdVal)));
            } else if (attrName.equals(STR_DXML_ASSOC)) {
                Collection<String> values = data.get(attrName);
                Collection<String> curAssociations = curAttrs.get(STR_DXML_ASSOC);
                for (String attrVal : values) {
                    String[] association = attrVal.split("#", 3);

                    String oldAttrVal = getDXMLAssocByDriverName(association[0], curAssociations);
                    if (oldAttrVal == null) {
                        throw new IdMUnitException("Failed to update attribute [" + STR_DXML_ASSOC + "] because a value matching the given driver DN was not found in the target object.");
                    }
                    assert oldAttrVal.length() > 0;

                    mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(attrName, oldAttrVal)));
                }
            } else {
                boolean b64 = false;
                Collection<String> removeValues = Collections.emptyList();
                if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_BIN)) {
                    b64 = true;
                    removeValues = data.get(attrName);
                    attrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_BIN);

                    Collection<byte[]> byteValues = BinaryAttrUtil.getBinValues(removeValues);
                    removeValues = BinaryAttrUtil.toB64(byteValues);

                } else if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_B64)) {
                    b64 = true;
                    removeValues = data.get(attrName);
                    attrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_B64);

                    removeValues = BinaryAttrUtil.getB64Values(removeValues);
                }

                Attribute attr = new BasicAttribute(attrName);
                if (b64) {
                    Collection<String> actualValues = curAttrs.get(attrName);
                    if ((actualValues != null) && !actualValues.isEmpty()) {
                        actualValues = BinaryAttrUtil.replaceAll(actualValues, BinaryAttrUtil.REGEX_NEWLINE, "");
                        removeValues = BinaryAttrUtil.replaceAll(removeValues, BinaryAttrUtil.REGEX_NEWLINE, "");
                        for (String actualValue : actualValues) {
                            for (String removeValue : removeValues) {
                                if (actualValue.equals(removeValue)) {
                                    attr.add(BinaryAttrUtil.toBytes(actualValue));
                                }
                            }
                        }
                    }
                } else {
                    removeValues = data.get(attrName);

                    Collection<String> actualValues = curAttrs.get(attrName);
                    // Only remove values if they are actually present on the object
                    if ((actualValues != null) && !actualValues.isEmpty()) {
                        for (String actualValue : actualValues) {
                            for (String expectedValue : removeValues) {
                                //TODO: Add configuration option at connector definition level to enable/disable case sensitivity for rex-ex comparisons
                                if (actualValue.matches(expectedValue)) {
                                    attr.add(actualValue);
                                }
                            }
                        }
                    }
                }

                //Only apply the modification if there are explicit values to remove, otherwise all values will be removed!
                if (attr.size() > 0) {
                    mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, attr));
                    
                } else {
                    
                }
            }
        }

        if (mods.size() > 0) {
            try {
                context.modifyAttributes(dn, (ModificationItem[])mods.toArray(new ModificationItem[mods.size()]));
            } catch (NamingException e) {
                if (e.getMessage().contains("16")) {
                    
                } else {
                    throw new IdMUnitException("Modification failure: Error: " + e.getMessage(), e);
                }
            }
        } else {
            
        }

        
    }

    public void opReplaceAttr(Map<String, Collection<String>> dataRow) throws IdMUnitException {
        modifyObject(dataRow, DirContext.REPLACE_ATTRIBUTE);
    }

    public void opAttrDoesNotExist(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        doValidate(expectedAttrs, true);
    }

    public void opValidateObjectDoesNotExist(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        String entryIdentifier = ConnectorUtil.getSingleValue(expectedAttrs, STR_DN);

        String dn = null;

        if (entryIdentifier.startsWith("(")) {
            // we have an ldap filter - see if we have any objects:
            String[] filterAndBase = entryIdentifier.split(STR_BASE_DN_DELIMITER);
            if (filterAndBase.length != 2) {
                throw new IdMUnitException("Error: value provied for DN appears to be an invalid ldap filter - it must be in the format of [LDAP FILTER]" + STR_BASE_DN_DELIMITER + "[LDAP BASE DN TO SEARCH]");
            }
            String filter = filterAndBase[0];
            String base = filterAndBase[1];
            dn = findObject(base, filter);
            if (dn != null) {
                throw new IdMUnitFailureException("An object was found when it was not expected. Object found: [" + dn + "]");
            }
        } else {
            // we appear to have a dn, see if it exists:
            dn = entryIdentifier;
            try {
                if (context.lookup(dn) != null) {
                    throw new IdMUnitFailureException("An object was found when it was not expected. Object found: [" + dn + "]");
                }
            } catch (NameNotFoundException e) {
                return;
            } catch (NamingException e) {
                throw new IdMUnitException("Failed while looking for dn: [" + dn + "]", e);
            }
        }

    }

    public void doValidate(Map<String, Collection<String>> expectedAttrs, boolean bIsAttrDoesNotExistTest) throws IdMUnitException {
        String dn = getTargetDn(expectedAttrs);

        

        //allow binary attributes (those prefixed with "bin_" or "b64") to be returned as byte[]
        BinaryAttrUtil.updateBinaryAttrsProperty(context, expectedAttrs.keySet());

        //TODO: refactor into single query with attribute list to remove need for additional operational attribute queries
        Map<String, Collection<String>> appAttrs = getAttributes(dn);

        Failures failures = new Failures();
        for (String attrName : expectedAttrs.keySet()) {
            if (attrName.equalsIgnoreCase(STR_DN) ||
                    attrName.equalsIgnoreCase(STR_USER_PASSWORD) ||
                    attrName.equalsIgnoreCase(STR_USER_OLD_PASSWORD) ||
                    attrName.equalsIgnoreCase(STR_UNICODE_PASSWORD)) {
                continue;
            }

            Collection<String> expectedValues = expectedAttrs.get(attrName);
            Collection<String> actualValues;
            if (operationalAttributes.contains(attrName)) {
                // Operational attributes are not returned from the server when
                // all attributes are requested so we need to read them
                // explicitly.
                actualValues = getAttributes(dn, new String[]{attrName}).get(attrName);
            } else {
                //strip prefix metadata from attribute name
                String appAttrName = attrName;
                if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_BIN)) {
                    appAttrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_BIN);
                } else if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_B64)) {
                    appAttrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_B64);
                }
                actualValues = appAttrs.get(appAttrName);
            }

            if (actualValues == null || actualValues.size() == 0) {
                if (bIsAttrDoesNotExistTest) {
                    continue;
                }
                // Did we expect a non populated value? If so we're done, move to the next one.
                if (IDMUNIT_EMPTY_VALUE.equalsIgnoreCase(expectedValues.iterator().next())) {
                    
                    continue;
                } else {
                    failures.add(attrName, expectedValues, new ArrayList<String>(Arrays.asList("Attribute was not populated")));
                    continue;
                }
            }

            compareAttributeValues(attrName, expectedValues, actualValues, failures);
        }

        if (failures.hasFailures()) {
            throw new IdMUnitFailureException(failures.toString());
        }
    }

    public void opChangePasswordAsUser(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {

        try {
            String oldPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_PASSWORD);
            if (oldPassword == null || oldPassword.length() == 0) {
                throw new IdMUnitException("Missing " + STR_USER_PASSWORD + " attribute");
            }

            String unicodePassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_UNICODE_PASSWORD);
            String newPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_NEW_PASSWORD);
            if (unicodePassword != null && unicodePassword.length() != 0) {
                changePasswordAsUserAD(expectedAttrs);
            } else if (newPassword != null && newPassword.length() != 0) {
                changePasswordAsUserIDV(expectedAttrs);
            } else {
                throw new IdMUnitException("Missing new password attribute.  User either newUserPassword for IDV, or unicodePassword for AD");
            }
        } catch (IdMUnitException e) {
            throw new IdMUnitFailureException("Failed to establish connection " + e.getMessage());
        }
    }

    private void changePasswordAsUserAD(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        DirContext userContext = null;
        try {
            userContext = getUserDirContext(expectedAttrs);
            String dn = getTargetDn(expectedAttrs);
            String oldPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_PASSWORD);
            String newPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_UNICODE_PASSWORD);
            
            // change password is a single ldap modify operation
            // that deletes the old password and adds the new password
            ModificationItem[] mods = new ModificationItem[2];

            String oldQuotedPassword = "\"" + oldPassword + "\"";
            byte[] oldUnicodePassword = oldQuotedPassword.getBytes("UTF-16LE");
            String newQuotedPassword = "\"" + newPassword + "\"";
            byte[] newUnicodePassword = newQuotedPassword.getBytes("UTF-16LE");

            mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                    new BasicAttribute("unicodePwd", oldUnicodePassword));
            mods[1] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                    new BasicAttribute("unicodePwd", newUnicodePassword));

            // Perform the password change
            userContext.modifyAttributes(dn, mods);

        } catch (IdMUnitException e) {
            throw new IdMUnitFailureException("Password validation failure: Error: " + e.getMessage());
        } catch (NamingException e) {
            throw new IdMUnitException("Failed changing password: " + e.getMessage());
        } catch (UnsupportedEncodingException e) {
            throw new IdMUnitException("Failed encoding password: " + e.getMessage());
        } finally {
            if (userContext != null) {
                try {
                    userContext.close();
                } catch (NamingException e) {
                    
                }
            }
        }
    }

    private void changePasswordAsUserIDV(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        InitialDirContext userContext = null;
        try {
            userContext = getUserDirContext(expectedAttrs);
            String dn = getTargetDn(expectedAttrs);
            
            String oldPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_PASSWORD);
            String newPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_NEW_PASSWORD);

            // change password is a single ldap modify operation
            // that deletes the old password and adds the new password
            ModificationItem[] mods = new ModificationItem[2];
            

            mods[0] = new ModificationItem(InitialDirContext.REMOVE_ATTRIBUTE, new BasicAttribute(STR_USER_PASSWORD, oldPassword));
            mods[1] = new ModificationItem(InitialDirContext.ADD_ATTRIBUTE, new BasicAttribute(STR_USER_PASSWORD, newPassword));

            // Perform the password change
            
            userContext.modifyAttributes(dn, mods);

        } catch (IdMUnitException e) {
            throw new IdMUnitFailureException("Password validation failure: Error: " + e.getMessage());
        } catch (NamingException e) {
            throw new IdMUnitException("Failed changing password: " + e.getMessage());
        } finally {
            if (userContext != null) {
                try {
                    userContext.close();
                } catch (NamingException e) {
                    
                }
            }
        }
    }

    //This method is not necessary, we have methods that do this already but is provided for clarity.
    public void opResetPasswordAsAdmin(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        try {
            if (expectedAttrs.containsKey(STR_UNICODE_PASSWORD) && expectedAttrs.containsKey(STR_USER_PASSWORD)) {
                opReplaceAttr(expectedAttrs);
            } else if (expectedAttrs.containsKey(STR_UNICODE_PASSWORD) && expectedAttrs.containsKey(STR_USER_PASSWORD)) {
                opChangeUserPassword(expectedAttrs);
            } else {
                throw new IdMUnitException("Missing new or old password attribute");
            }
        } catch (IdMUnitException e) {
            throw new IdMUnitFailureException("Failed to establish connection " + e.getMessage());
        }
    }


    public void opValidatePassword(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        try {
            String dn = getTargetDn(expectedAttrs);
            
            getUserDirContext(expectedAttrs);
            
        } catch (IdMUnitException e) {
            throw new IdMUnitFailureException("Password validation failure: Error: " + e.getMessage());
        }
    }


    private InitialDirContext getUserDirContext(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        InitialDirContext userConn = null;
        try {
            String dn = getTargetDn(expectedAttrs);
            String passwordVal = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_PASSWORD);
            if (passwordVal == null || passwordVal.length() == 0) {
                throw new IdMUnitFailureException("Missing " + STR_USER_PASSWORD + " attribute.");
            }
            
            Map<String, String> userConfig = new HashMap<String, String>(this.config);
            userConfig.put(CONFIG_USER, dn);
            userConfig.put(CONFIG_PASSWORD, passwordVal);
            userConn = LdapConnectionHelper.createLdapConnection(userConfig);
        } catch (IdMUnitException e) {
            throw new IdMUnitFailureException("Password validation failure: Error: " + e.getMessage());
        }

        return userConn;
    }

    /*
     * Executes a password administrative reset, standard ldap (eDirectory style)
     */
    public void opResetUserPassword(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {

        String dn = getTargetDn(expectedAttrs);

        String newPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_PASSWORD);
        if (newPassword == null || newPassword.length() == 0) {
            throw new IdMUnitException("Missing " + STR_USER_PASSWORD + " attribute.");
        }

        ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", newPassword));

        try {
            // Perform the password reset
            context.modifyAttributes(dn, mods);
        } catch (NamingException e) {
            throw new IdMUnitException("Failed changing password: " + e.getMessage());
        }
    }

    /*
     * Executes a password administrative reset, standard ldap (eDirectory style)
     */
    public void opResetUserPasswordUnicode(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {

        String dn = getTargetDn(expectedAttrs);

        String newPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_UNICODE_PASSWORD);
        if (newPassword == null || newPassword.length() == 0) {
            throw new IdMUnitException("Missing " + STR_UNICODE_PASSWORD + " attribute.");
        }

        try {
            String newQuotedPassword = "\"" + newPassword + "\"";
            byte[] newUnicodePassword = newQuotedPassword.getBytes("UTF-16LE");
            ModificationItem[] mods = new ModificationItem[1];
            mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("unicodePwd", newUnicodePassword));

            // Perform the password reset
            context.modifyAttributes(dn, mods);
        } catch (UnsupportedEncodingException e) {
            throw new IdMUnitException("Failed encoding password: " + e.getMessage());
        } catch (NamingException e) {
            throw new IdMUnitException("Failed changing password: " + e.getMessage());
        }
    }

    /*
     * Executes a password change rather than an administrative reset, standard ldap (eDirectory style)
     */
    public void opChangeUserPassword(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        String dn = getTargetDn(expectedAttrs);

        String oldPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_OLD_PASSWORD);
        if (oldPassword == null || oldPassword.length() == 0) {
            throw new IdMUnitException("Missing " + STR_USER_OLD_PASSWORD + " attribute.");
        }
        String newPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_PASSWORD);
        if (newPassword == null || newPassword.length() == 0) {
            throw new IdMUnitException("Missing " + STR_USER_PASSWORD + " attribute.");
        }
        // change password is a single ldap modify operation
        // that deletes the old password and adds the new password
        ModificationItem[] mods = new ModificationItem[2];

        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                new BasicAttribute("userPassword", oldPassword));
        mods[1] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                new BasicAttribute("userPassword", newPassword));

        try {
            // Perform the password change
            context.modifyAttributes(dn, mods);
        } catch (NamingException e) {
            throw new IdMUnitException("Failed changing password: " + e.getMessage());
        }
    }

    /*
     * Executes a password change rather than an administrative reset, Active Directory (unicode) style.
     */
    public void opChangeUserPasswordUnicode(Map<String, Collection<String>> expectedAttrs) throws IdMUnitException {
        String dn = getTargetDn(expectedAttrs);

        String oldPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_USER_OLD_PASSWORD);
        if (oldPassword == null || oldPassword.length() == 0) {
            throw new IdMUnitException("Missing " + STR_USER_OLD_PASSWORD + " attribute.");
        }
        String newPassword = ConnectorUtil.getSingleValue(expectedAttrs, STR_UNICODE_PASSWORD);
        if (newPassword == null || newPassword.length() == 0) {
            throw new IdMUnitException("Missing " + STR_UNICODE_PASSWORD + " attribute; opChangeUserPasswordUnicode is normally used for AD; is this an AD system?");
        }
        // change password is a single ldap modify operation
        // that deletes the old password and adds the new password
        ModificationItem[] mods = new ModificationItem[2];

        try {
            // Firstly delete the "unicdodePwd" attribute, using the old
            // password
            // Then add the new password,Passwords must be both Unicode and a
            // quoted string
            String oldQuotedPassword = "\"" + oldPassword + "\"";
            byte[] oldUnicodePassword = oldQuotedPassword.getBytes("UTF-16LE");
            String newQuotedPassword = "\"" + newPassword + "\"";
            byte[] newUnicodePassword = newQuotedPassword.getBytes("UTF-16LE");

            mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                    new BasicAttribute("unicodePwd", oldUnicodePassword));
            mods[1] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                    new BasicAttribute("unicodePwd", newUnicodePassword));

            // Perform the password change
            context.modifyAttributes(dn, mods);

        } catch (NamingException e) {
            throw new IdMUnitException("Failed changing password: " + e.getMessage());
        } catch (UnsupportedEncodingException e) {
            throw new IdMUnitException("Failed encoding password: " + e.getMessage());
        }
    }

    public void setup(Map<String, String> serverConfig) throws IdMUnitException {
        server = serverConfig.get(CONFIG_SERVER);
        String additionalOpAttrs = serverConfig.get("operationalAttributes");

        if (additionalOpAttrs != null) {
            String[] opAttrs = additionalOpAttrs.split(" *, *");

            for (String opAttr : opAttrs) {
                operationalAttributes.add(opAttr);
            }
        }

        // create a defensive copy of the config.
        this.config = Collections.unmodifiableMap(serverConfig); // Config is stored for use in opValidatePassword.
        this.context = LdapConnectionHelper.createLdapConnection(new HashMap<String, String>(serverConfig));
    }

    public void tearDown() throws IdMUnitException {
        LdapConnectionHelper.destroyLdapConnection(context);
    }

    private String findObject(String base, String filter) throws IdMUnitException {
        return findObject(base, filter, SearchControls.SUBTREE_SCOPE);
    }

    private String findObject(String base, String filter, int scope) throws IdMUnitException {
        if (null == filter) {
            throw new IllegalArgumentException("Search filter is null");
        }

        if ((scope != SearchControls.SUBTREE_SCOPE) &&
                (scope != SearchControls.OBJECT_SCOPE) &&
                (scope != SearchControls.ONELEVEL_SCOPE)) {
            throw new IllegalArgumentException("Invalid search scope: " + scope);
        }

        String resolvedDn = null;

        SearchControls ctls = new SearchControls();
        ctls.setSearchScope(scope);

        try {
            // Find users with a matching ID
            NamingEnumeration<SearchResult> results = this.context.search(base, filter, ctls);
            SearchResult sr;
            int resultCtr = 0;
            while (results.hasMoreElements()) {
                ++resultCtr;
                sr = (SearchResult)results.next();
                if (resultCtr == 1) {
                    if (sr.getName() != null && sr.getName().length() > 0) {
                        resolvedDn = sr.getName() + "," + base;
                    } else {
                        resolvedDn = base;
                    }
                    
                } else {
                    
                }
            }
        } catch (NamingException e) {
            throw new IdMUnitException("Object Lookup for filter [" + filter + "], base [" + base + "] Failed: " + e.getMessage(), e);
        }
        return resolvedDn;
    }

    private TreeMap<String, Collection<String>> getAttributes(String dn) throws IdMUnitException {
        try {
            DirContext tmp = (DirContext)context.lookup(dn);
            if (tmp != null) {
                tmp.close(); //this is necessary in order to keep the parent connection ctx clean enough to be pooled/managed as week references inside of the parent DirContext will prevent proper pooling
            }
        } catch (NameNotFoundException e) {
            throw new IdMUnitException("Could not find object: [" + dn + "] to retrieve attributes.", e);
        } catch (NamingException e) {
            throw new IdMUnitException("Error resolving '" + dn + "'.", e);
        }

        try {
            return attributesToMap(context.getAttributes(dn));
        } catch (NamingException e) {
            throw new IdMUnitException("Error reading attributes for '" + dn + "'.", e);
        }
    }

    private TreeMap<String, Collection<String>> getAttributes(String dn, String[] attrs) throws IdMUnitException {
        try {
            Attributes operationalAttrs = context.getAttributes(dn, attrs);
            return attributesToMap(operationalAttrs);
        } catch (NamingException e) {
            throw new IdMUnitException("Error reading attributes for '" + dn + "'.", e);
        }
    }

    protected String getRequiredDn(Map<String, Collection<String>> data) throws IdMUnitException {
        String dn = ConnectorUtil.getSingleValue(data, STR_DN);

        if (dn == null) {
            throw new IdMUnitException("A Distinguished Name must be supplied in column '" + STR_DN + "'");
        }

        //there's no scenario where prefixed and postfixed whitespace are significant
        return dn.trim();
    }

    protected String getTargetDn(Map<String, Collection<String>> data) throws IdMUnitException {

        String dn = ConnectorUtil.getSingleValue(data, STR_DN);

        if (dn == null) {
            throw new IdMUnitException("A Distinguished Name must be supplied in column '" + STR_DN + "'");
        }

        if (!dn.trim().equalsIgnoreCase(dn)) {
            throw new IdMUnitException("WARNING: your DN specified: [" + dn + "] is either prefixed or postfixed with whitespace!  Please correct, then retest.");
        }

        // Detect LDAP filter in the DN
        if (dn.startsWith("(")) {
            // Search for the user by a standard LDAP filter
            // The format for this field is "<filter>,base=<container dn>"
            int startOfBase = dn.indexOf(STR_BASE_DN_DELIMITER);
            if (startOfBase == -1) {
                throw new IdMUnitException("Check the dn or LDAP filter specified in the spreadsheet. Should be listed in the form (LDAPFilter),base=LDAPSearchBase.  Example: (&(objectClass=inetOrgPerson)(cn=testuser1)),base=o=users.");
            }

            String filter = dn.substring(0, startOfBase);
            String base = dn.substring(startOfBase + STR_BASE_DN_DELIMITER.length());

            dn = findObject(base, filter);
        } else {
            // Detect standard wildcard token * in the ID
            String[] nameComponents = dn.split("(?<!\\\\),");
            String idVal = nameComponents[0];
            if (idVal.indexOf("*") == -1) {
                return dn;
            }
            // cn=TIDMTST*1,ou=users,o=myorg
            

            String base = dn.substring(dn.indexOf(nameComponents[1]));
            String filter = "(" + idVal + ")";
            

            dn = findObject(base, filter);
        }

        if (dn == null || dn.length() < 1) {
            throw new IdMUnitException("Failed to resolve target DN: Check the dn or LDAP filter specified in the spreadsheet to ensure it returns results.  Recommended: test the filter in an LDAP browser first.");
        }

        dn = dn.replaceAll("/", "\\\\/");
        dn = dn.replaceAll("\"", "");

        return dn;
    }

    private Object lookupObject(String dn) throws IdMUnitException {
        try {
            return context.lookup(dn);
        } catch (NamingException e) {
            return null;
        }
    }

    private void modifyObject(Map<String, Collection<String>> dataRow, int operationType) throws IdMUnitException {
        String dn = getTargetDn(dataRow);
        

        List<ModificationItem> mods = new ArrayList<ModificationItem>();
        for (String attrName : dataRow.keySet()) {
            if (attrName.equalsIgnoreCase(STR_DN)) {
                continue;
            } else if (attrName.equals(STR_UNICODE_PASSWORD)) {
                byte[] unicodePwdVal = getUnicodeBytes(ConnectorUtil.getSingleValue(dataRow, STR_UNICODE_PASSWORD));
                mods.add(new ModificationItem(operationType, new BasicAttribute(attrName, unicodePwdVal)));
            } else if (attrName.equals(STR_DXML_ASSOC) && operationType == DirContext.REPLACE_ATTRIBUTE) {
                Collection<String> curAssociations = getAttributes(dn, new String[]{STR_DXML_ASSOC}).get(STR_DXML_ASSOC);
                for (String attrVal : dataRow.get(attrName)) {
                    String[] association = attrVal.split("#", 3);

                    if (curAssociations != null) {
                        String oldAttrVal = getDXMLAssocByDriverName(association[0], curAssociations);
                        if (oldAttrVal != null) {
                            assert oldAttrVal.length() > 0;

                            // If the new association doesn't have a the path
                            // component (the third component), use the path
                            // component from the current association.
                            if (association.length == 2) {
                                String[] oldAssociation = oldAttrVal.split("#", 3);
                                if (oldAssociation.length == 3) {
                                    attrVal = association[0] + "#" + association[1] + "#" + oldAssociation[2];
                                }
                            }

                            mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(attrName, oldAttrVal)));
                        }
                    }
                    mods.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute(attrName, attrVal)));
                    continue;
                }
            } else if (attrName.equals(STR_USER_PASSWORD)) {
                // don't allow password changes along with modifies: instead use opChangeUserPassword (to execute old/new password change), or opResetUserPassword to execute an administrative password change.
                if (allowPasswordResetOnModifyOp) {
                    // using 'newPassword'. Only administrative password resets are supported during modifies.  Use opChangeUserPassword to do a user password change.
                    String newPassword = dataRow.get(STR_USER_PASSWORD).toString().substring("[".length(), dataRow.get(STR_USER_PASSWORD).toString().length() - "]".length());
                    mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", newPassword)));
                    // TODO: find out why we would modify the password now; rather than modify it along with the rest of the attributes as indicated by allowPasswordResetOnModifyOp . . .
                    //context.modifyAttributes(dn, changePassword);
                } else {
                    // We decided password changes/resets deserve their own first class function (opChangeUserPassword, opChangeUserPasswordUnicode, and opResetPasswordAsAdmin)
                     // While it is possible to guess whether something is a password change vs password reset just by available columns; we felt doing it this way was less ambiguous.
                    throw new IdMUnitException("ERROR: do not attempt a password reset passwords at the same time as other modifies. If you must have this functionality, set <allowPasswordResetOnModifyOp>true</allowPasswordResetOnModifyOp> in your config, and retest.");
                }

            } else if (STR_USER_OLD_PASSWORD.equals(attrName)) {
                // Don't attempt to do any validation on the oldUserPassword.
                continue;
            } else {
                Attribute attr;
                Collection<String> values = dataRow.get(attrName);
                if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_BIN)) {
                    attrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_BIN);
                    attr = new BasicAttribute(attrName);

                    Collection<byte[]> byteList = BinaryAttrUtil.getBinValues(values);
                    for (byte[] bytes : byteList) {
                        attr.add(bytes);
                    }
                    values = BinaryAttrUtil.toB64(byteList);
                } else if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_B64)) {
                    attrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_B64);
                    attr = new BasicAttribute(attrName);

                    Collection<String> encodedList = BinaryAttrUtil.getB64Values(values);
                    Collection<byte[]> byteList = BinaryAttrUtil.toBytes(encodedList);
                    for (byte[] bytes : byteList) {
                        attr.add(bytes);
                    }
                    values = encodedList;
                } else {
                    attr = new BasicAttribute(attrName);
                    for (Iterator<String> j = values.iterator(); j.hasNext(); ) {
                        attr.add(j.next());
                    }
                }

                mods.add(new ModificationItem(operationType, attr));
                
            }
        }

        if (mods.size() > 0) {
            try {
                context.modifyAttributes(dn, (ModificationItem[])mods.toArray(new ModificationItem[mods.size()]));
            } catch (NamingException e) {
                if (e.getMessage().contains("16")) {
                    
                } else {
                    throw new IdMUnitException("Modification failure: Error: " + e.getMessage(), e);
                }
            }
        } else {
            
        }

        
    }

    protected void compareAttributeValues(String attrName, Collection<String> expected, Collection<String> actual, Failures failures) throws IdMUnitException {

        boolean b64Compare = false;
        if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_BIN)) {
            b64Compare = true;
            attrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_BIN);

            Collection<byte[]> byteList = BinaryAttrUtil.getBinValues(expected);
            expected = BinaryAttrUtil.toB64(byteList);
        }

        if (attrName.toLowerCase().startsWith(BinaryAttrUtil.ATTR_PREFIX_B64)) {
            b64Compare = true;
            attrName = BinaryAttrUtil.stripPrefix(attrName, BinaryAttrUtil.ATTR_PREFIX_B64);

            expected = BinaryAttrUtil.getB64Values(expected);
        }

        if (b64Compare) {
            //literal string comparison w/o line endings

            expected = BinaryAttrUtil.replaceAll(expected, BinaryAttrUtil.REGEX_NEWLINE, "");
            actual = BinaryAttrUtil.replaceAll(actual, BinaryAttrUtil.REGEX_NEWLINE, "");
            Collection<String> unmatched = new LinkedList<String>(actual);
            outer:
            for (String expectedValue : expected) {
                for (Iterator<String> i = unmatched.iterator(); i.hasNext(); ) {
                    String actualValue = i.next();
                    if (expectedValue.equals(actualValue)) {
                        
                        i.remove();
                        continue outer;
                    }
                }

                failures.add(attrName, expected, actual);
                return;
            }
        } else {
            //regex compare (default)

            Collection<String> unmatched = new LinkedList<String>(actual);
            outer:
            for (String expectedValue : expected) {
                Pattern p = Pattern.compile(expectedValue, insensitive ? Pattern.CASE_INSENSITIVE : Pattern.DOTALL);
                for (Iterator<String> i = unmatched.iterator(); i.hasNext(); ) {
                    String actualValue = i.next();

                    if (p.matcher(actualValue).matches()) {
                        
                        i.remove();
                        continue outer;
                    }
                }

                failures.add(attrName, expected, actual);
                return;
            }
        }
    }

    /**+
     * Deletes the specified subtree.
     * This method is useful for cleaning up after tests and making tests parrallelizable. With a powerful cleanup
     * mechanism, it's possible to create and teardown containers to isolate the scope of test impact and reduce the
     * likelihood of leftovers biasing previous test runs. It also reduce the number of cleanup operations necessary
     * for test cleanup.
     * @param data A map of parameters (required)
     *    "dn" (required) -> The root of the subtree to delete. Cannot be a LDAP search filter (one subtree may be
     *        deleted per operation). "" or the tree root may not be deleted.
     *    "deleteRoot" (optional) -> Whether to delete the root of the subtree. Legal values are "true" and "false".
     *        The default is "false".
     *    "includeFilter" (optional) -> A LDAP filter indicating which objects in the sutbtree should be deleted.
     *        By default, no objects are included so no objects are deleted. The exclude filter trumps the include
     *        filter.
     *    "excludeFilter" (optional) -> A LDAP filter indicating which object in the subtree should [not] be deleted.
     *        By default, only the bind DN and its parent containers are excluded. The exclude filter trumps the
     *        include filter.
     * @throws IdMUnitException
     */
    public void opDeleteSubtree(Map<String, Collection<String>> data) throws IdMUnitException {
        //make a defensive copy
        data = new HashMap<String, Collection<String>>(data);

        String dn = getRequiredDn(data);

        if (dn.length() == 0) {
            throw new IdMUnitException("Subtree deletion at the tree root isn't supported");
        }

        if (lookupObject(dn) == null) {
            
            //already deleted
            return;
        }

        String deleteRoot = ConnectorUtil.getSingleValue(data, "deleteRoot");
        boolean deleteParent = "true".equalsIgnoreCase(deleteRoot);

        String includeFilter = ConnectorUtil.getSingleValue(data, "includeFilter");
        if ((null == includeFilter) || "".equalsIgnoreCase(includeFilter.trim())) {
            
            //nothing to do; must specify include filter to actually delete anything
            return;
        }

        String excludeFilter = ConnectorUtil.getSingleValue(data, "excludeFilter");

        String boundUserDn = this.config.get(BasicConnector.CONFIG_USER);

        deleteSubtree(dn, boundUserDn, deleteParent, includeFilter, excludeFilter);
    }

    private void deleteSubtree(String parentDn, String boundUserDn, boolean deleteParent, String includeFilter, String excludeFilter) throws IdMUnitException {
        NamingEnumeration bindings = null;
        try {
            bindings = this.context.listBindings(parentDn);
            while (bindings.hasMore()) {
                Binding element = (Binding) bindings.next();
                String childName = element.getName();
                String childDn = childName + "," + parentDn;

                deleteSubtree(childDn, boundUserDn, true, includeFilter, excludeFilter);
            }

            if (deleteParent) {
                boolean exclude = parentDn.equalsIgnoreCase(boundUserDn) ||
                        ((null != excludeFilter) && (null != findObject(parentDn, excludeFilter, SearchControls.OBJECT_SCOPE)));
                if (!exclude && (null != findObject(parentDn, includeFilter, SearchControls.OBJECT_SCOPE))) {
                    this.context.unbind(parentDn);
                } else {
                    
                }
            }
        } catch (NamingException e) {
            
        } finally {
            if (null != bindings) {
                try {
                    bindings.close();
                } catch (NamingException  e) {
                    //ignore
                }
            }
        }
    }
}
