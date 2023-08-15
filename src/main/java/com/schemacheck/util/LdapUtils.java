package com.schemacheck.util;

import com.schemacheck.model.Operation;
import com.schemacheck.model.OperationData;

import javax.naming.Binding;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.util.*;
import java.util.stream.Collectors;

public class LdapUtils {

    private final DirContext context;

    public LdapUtils(DirContext context) {
        this.context = context;
    }

    public Set<String> getBasicAttributeValueNames(Boolean recurse, Set<String> objectClass, String... basicAttributeNames) {
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
    public List<Attributes> getObjectClassAttributes(boolean recurse, String... objectClasses) {
        List<Attributes> searchResults = new ArrayList<>();
        for (String objectClass : objectClasses) {
            Attributes attributes = null;
            try {
                attributes = ((DirContext) context.getSchema("").lookup("ClassDefinition/" + objectClass)).getAttributes("");
                searchResults.add(attributes);
            } catch (NamingException e) {
                try {
                    Iterator<String> objectIterator = getXndsMappedObjectClassName(objectClass).iterator();
                    if (objectIterator.hasNext()) {
                        objectClass = objectIterator.next();
                        attributes = ((DirContext) context.getSchema("").lookup("ClassDefinition/" + objectClass)).getAttributes("");
                        searchResults.add(attributes);
                    }

                } catch (NamingException ex) {
                    throw new RuntimeException(String.format("Failed to get Class definition for the \"%s\" object class.\n\t", objectClass), e);
                }
            }
            if (recurse) {
                if (null != attributes && null != attributes.get("sup")) {
                    try {
                        searchResults.addAll(getObjectClassAttributes(true, (String) attributes.get("sup").get()));
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
    Set<String> getXndsMappedObjectClassName(String... xndsNames) {
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

    public Set<String> getMissingRequiredAttributeNames(Operation operation) {
        Set<String> objectClasses = new HashSet<>(Arrays.asList(IdmTestUtils.getAttributes(operation, "ObjectClass")));
        return getBasicAttributeValueNames(true, objectClasses, "must").stream()
                .filter(attributeName -> operation
                        .getData()
                        .stream()
                        .map(OperationData::getAttribute)
                        .collect(Collectors.toSet())
                        .contains(attributeName))
                .collect(Collectors.toSet());
    }

}
