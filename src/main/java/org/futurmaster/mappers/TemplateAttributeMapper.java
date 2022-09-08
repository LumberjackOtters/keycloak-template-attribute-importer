/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.futurmaster.mappers;

import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.common.util.CollectionUtil;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.saml.mappers.SamlMetadataDescriptorUpdater;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.StringUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class TemplateAttributeMapper extends AbstractIdentityProviderMapper implements IdentityProviderMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String TEMPLATE = "template";
    public static final String USER_ATTRIBUTE = "user.attribute";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    public static final Map<String, UnaryOperator<String>> TRANSFORMERS = new HashMap<>();

    public static final List<String> NAME_FORMATS = Arrays.asList(JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC.name(), JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.name(), JBossSAMLURIConstants.ATTRIBUTE_FORMAT_UNSPECIFIED.name());
    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(TEMPLATE);
        property.setLabel("Template");
        property.setHelpText("Template to use to format the username to import.  Substitutions are enclosed in ${}.  For example: '${ALIAS}.${NAMEID}'.  ALIAS is the provider alias.  NAMEID is that SAML name id assertion. \n"
          + "The substitution can be converted to upper or lower case by appending |uppercase or |lowercase to the substituted value, e.g. '${NAMEID | lowercase} \n");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("${ALIAS}.${NAMEID}");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(USER_ATTRIBUTE);
        property.setLabel("User Attribute Name");
        property.setHelpText("User attribute name to store saml attribute.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);

        TRANSFORMERS.put("uppercase", String::toUpperCase);
        TRANSFORMERS.put("lowercase", String::toLowerCase);
    }

    public static final String PROVIDER_ID = "saml-template-attribute-idp-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Preprocessor";
    }

    @Override
    public String getDisplayType() {
        return "Template Attribute Importer";
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }

        List<String> templateValuesInContext = findTemplateValuesInContext(mapperModel, context);
        if (!templateValuesInContext.isEmpty()) { 
             context.setUserAttribute(attribute, templateValuesInContext);
        }
    }


    private void setIfNotEmpty(Consumer<String> consumer, List<String> values) {
        if (values != null && !values.isEmpty()) {
            consumer.accept(values.get(0));
        }
    }

    private void setIfNotEmptyAndDifferent(Consumer<String> consumer, Supplier<String> currentValueSupplier, List<String> values) {
        if (values != null && !values.isEmpty() && !values.get(0).equals(currentValueSupplier.get())) {
            consumer.accept(values.get(0));
        }
    }

    private static final Pattern SUBSTITUTION = Pattern.compile("\\$\\{([^}]+?)(?:\\s*\\|\\s*(\\S+)\\s*)?\\}");

    private List<String> findTemplateValuesInContext(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType)context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        String template = mapperModel.getConfig().get(TEMPLATE);
        Matcher m = SUBSTITUTION.matcher(template);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String variable = m.group(1);
            UnaryOperator<String> transformer = Optional.ofNullable(m.group(2)).map(TRANSFORMERS::get).orElse(UnaryOperator.identity());

            if (variable.equals("ALIAS")) {
                m.appendReplacement(sb, transformer.apply(context.getIdpConfig().getAlias()));
            } else if (variable.equals("UUID")) {
                m.appendReplacement(sb, transformer.apply(KeycloakModelUtils.generateId()));
            } else if (variable.equals("NAMEID")) {
                SubjectType subject = assertion.getSubject();
                SubjectType.STSubType subType = subject.getSubType();
                NameIDType subjectNameID = (NameIDType) subType.getBaseID();
                m.appendReplacement(sb, transformer.apply(subjectNameID.getValue()));
            } else {
                m.appendReplacement(sb, m.group(1));
            }

        }
        m.appendTail(sb);

        List<String> values = Arrays.asList(sb.toString());

        return values;                                                                                                                                     
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }                           

        List<String> templateValuesInContext = findTemplateValuesInContext(mapperModel, context);
        
        List<String> currentAttributeValues = user.getAttributes().get(attribute);
        if (templateValuesInContext == null) {
            // attribute no longer sent by brokered idp, remove it
            user.removeAttribute(attribute);
        } else if (currentAttributeValues == null) {
            // new attribute sent by brokered idp, add it
            user.setAttribute(attribute, templateValuesInContext);
        } else if (!CollectionUtil.collectionEquals(templateValuesInContext, currentAttributeValues)) {
            // attribute sent by brokered idp has different values as before, update it
            user.setAttribute(attribute, templateValuesInContext);
        }
        // attribute already set
    }

    @Override
    public String getHelpText() {
        return "Import template if it complies into the specified user attribute.";
    }

}