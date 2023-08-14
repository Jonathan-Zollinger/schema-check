package com.schemacheck.util;

import com.schemacheck.model.Connector;
import com.schemacheck.model.ConnectorAttribute;
import com.schemacheck.model.IdmUnitTest;

import javax.naming.Binding;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class LdapUtils {

    static DirContext context;

    public LdapUtils(DirContext context) {
        LdapUtils.context = context;
    }


    /**
     * Returns the values for any basic attributes from attributesList whose name is case insensitively matched against basicAttributeNames.
     *
     * @param objectClass         names of object classes whose attributes are to be queried.
     * @param basicAttributeNames The names of the attributes whose basic attribute names are to be returned.
     * @return The names of the basic attributes assigned the provided basicAttributeNames in the given Attributes list.
     * @throws RuntimeException If a Naming Exception is encountered when querying the schema definition for any
     *                          attributes.
     */
    public static BasicAttribute[] getBasicAttributes(Boolean recurse, Set<String> objectClass, String... basicAttributeNames) throws RuntimeException {
        List<Attributes> attributesList = getObjectClassAttributes(recurse, objectClass.toArray(new String[0]));
        Set<BasicAttribute> basicAttributes = new HashSet<>();
        for (Attributes attributes : attributesList) {
            NamingEnumeration<? extends Attribute> allResults = attributes.getAll();
            while (allResults.hasMoreElements()) {
                Attribute nextElement = allResults.nextElement();
                if (Arrays.stream(basicAttributeNames).anyMatch(nextElement.getID()::equalsIgnoreCase)) {
                    NamingEnumeration<?> attributeValues;
                    try {
                        attributeValues = nextElement.getAll();
                    } catch (NamingException e) {
                        throw new RuntimeException(String.format("Failed to query all elements in the \"%s\" element.", nextElement.getID()), e);
                    }
                    while (attributeValues.hasMoreElements()) {
                        Object thisElement = attributeValues.nextElement();
                        BasicAttribute basicAttribute = thisElement instanceof BasicAttribute ? ((BasicAttribute) thisElement) : null;
                        if (null == basicAttribute) { throw new RuntimeException ("unexpected data type");}
                        basicAttributes.add((basicAttribute));
                    }
                }
            }
        }
        return basicAttributes.toArray(new BasicAttribute[0]);
    }

    public static Set<String> getBasicAttributeValueNames(Boolean recurse, Set<String> objectClass, String... basicAttributeNames) throws RuntimeException {
        Set<String> basicAttributeValues = new HashSet<>();
        for (Attributes attributes : getObjectClassAttributes(recurse, objectClass.toArray(new String[0]))) {
            NamingEnumeration<? extends Attribute> allResults = attributes.getAll();
            while (allResults.hasMoreElements()) {
                Attribute nextElement = allResults.nextElement();
                if (Arrays.stream(basicAttributeNames).anyMatch(nextElement.getID()::equalsIgnoreCase)) {
                    NamingEnumeration<?> ne;
                    try {
                        ne = nextElement.getAll();
                    } catch (NamingException e) {
                        throw new RuntimeException(String.format("Failed to query all elements in the \"%s\" element.", nextElement.getID()), e);
                    }
                    while (ne.hasMoreElements()) {
                        basicAttributeValues.add(String.valueOf(ne.nextElement()));
                    }
                }
            }
        }
        return basicAttributeValues;
    }


    /**
     * Retrieves the attributes of an object class as well as the attributes of the object class's super classes.
     *
     * @param objectClasses The name of the object class whose attributes will be returned
     * @return The attributes assigned to both an object class and its super classes.
     * @throws RuntimeException If a Naming Exception is encountered when querying the object class definition(s).
     */
    public static List<Attributes> getObjectClassAttributes(boolean recurse, String... objectClasses) throws RuntimeException {
        List<Attributes> searchResults = new ArrayList<>();
        for (String objectClass : objectClasses) {
            Attributes Attributes;
            try {
                Attributes = ((DirContext) context.getSchema("").lookup("ClassDefinition/" + objectClass)).getAttributes("");
                searchResults.add(Attributes);
            } catch (NamingException e) {
                try {
                    objectClass = getXndsMappedObjectClassName(objectClass).iterator().next();
                    Attributes = ((DirContext) context.getSchema("").lookup("ClassDefinition/" + objectClass)).getAttributes("");
                    searchResults.add(Attributes);
                } catch (NamingException ex) {
                    throw new RuntimeException(String.format("Failed to get Class definition for the \"%s\" object class.\n\t", objectClass), e);
                }
            }
            if (recurse) {
                if (null != Attributes.get("sup")) {
                    try {
                        searchResults.addAll(getObjectClassAttributes(true, (String) Attributes.get("sup").get()));
                    } catch (NamingException e) {
                        throw new RuntimeException(String.format("Failed to get the object class definition for the \"%s\" object " +
                                "class.\n\t", objectClass), e);
                    }
                }
            }
        }
        return searchResults;
    }

    /**
     * Returns the object class name associated with an LDAP synonym.
     *
     * @param xndsNames name of the LDAP synonym which is mapped in an object class's "x-nds_name" property
     * @return The object class associated with the LDAP synonym.
     * @throws RuntimeException if Naming exceptions are encountered when querying the ldap service.
     * @see <a href="https://docs.oracle.com/javase/jndi/tutorial/basics/directory/attrnames.html>JNDI Tutorial</a>
     */
    static Set<String> getXndsMappedObjectClassName(String... xndsNames) throws RuntimeException {
        Set<String> xndsNamesSet = Arrays.stream(xndsNames).map(String::toLowerCase).collect(Collectors.toSet());
        Set<String> mappedObjectClass = new HashSet<>();
        NamingEnumeration<Binding> allTheObjectClasses;
        try {
            allTheObjectClasses = context.getSchema("").listBindings("classDefinition");
        } catch (NamingException e) {
            throw new RuntimeException("Failed to query all class definition bindings", e);
        }
        while (allTheObjectClasses.hasMoreElements()) {
            Binding thisBinding = allTheObjectClasses.nextElement();
            Set<String> returnedString;
            try {
                returnedString = getBasicAttributeValueNames(false, Collections.singleton(thisBinding.getName()), "x-nds_name", "x-nds_naming");
            } catch (RuntimeException e) {
                continue;
            }
            if (returnedString.stream().map(String::toLowerCase).anyMatch(xndsNamesSet::contains)) {
                mappedObjectClass.add(thisBinding.getName());
            }
        }
        return mappedObjectClass;
    }

    public static Set<String> getMissingRequiredAttributeNames(Connector connector) throws RuntimeException {
        Set<String> requiredAttributes;
        Set<String> objectClasses = Arrays.stream(IdmTestUtils.getAttributes(connector, "ObjectClass")).map(ConnectorAttribute::getName).collect(Collectors.toSet());
        requiredAttributes = getBasicAttributeValueNames(true, objectClasses , "must");
        return requiredAttributes.stream()
                .filter(req -> connector.getAttributes().stream().map(ConnectorAttribute::getName).noneMatch(req::equalsIgnoreCase))
                .collect(Collectors.toSet());
    }

}
