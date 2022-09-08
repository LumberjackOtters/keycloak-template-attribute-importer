FROM jboss/keycloak:16.1.1
COPY saml-template-attribute-idp-mapper-1.0.0.jar /opt/jboss/keycloak/standalone/deployments
# configure jboss
# COPY standalone.xml /opt/jboss/keycloak/standalone/configuration/
# # custom themes
# COPY /themes/custom /opt/jboss/keycloak/themes/custom