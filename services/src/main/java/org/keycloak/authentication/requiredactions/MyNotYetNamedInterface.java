package org.keycloak.authentication.requiredactions;

import org.jboss.logging.Logger;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.RecoveryAuthnCodesCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;

public interface MyNotYetNamedInterface extends RequiredActionFactory {

    Logger log = Logger.getLogger(MyNotYetNamedInterface.class);

    String ADD_RECOVERY_CODES = "add-recovery-codes";

    List<ProviderConfigProperty> ADD_RECOVERY_CODES_CONFIG_PROPERTIES = addRecoveryCodesConfig();

    static List<ProviderConfigProperty> addRecoveryCodesConfig() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(ADD_RECOVERY_CODES)
                .label("Add Recovery Codes")
                .helpText("""
                        If this option is enabled, the user will be required to configure recovery codes following the OTP configuration.
                        If the user already has recovery codes configured, Keycloak will not ask for setting them up.
                        As a prerequisite, enable the recovery codes required action and enable recovery codes in your authentication flow.""")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(false)
                .add()
                .build();
    }

    @Override
    default List<ProviderConfigProperty> getConfigMetadata() {
        List<ProviderConfigProperty> configs = new ArrayList<>(List.copyOf(MAX_AUTH_AGE_CONFIG_PROPERTIES));
        configs.addAll(List.copyOf(ADD_RECOVERY_CODES_CONFIG_PROPERTIES));
        return configs;
    }

    default void doAnything(RequiredActionContext context) {
        if (context.getConfig() != null &&
                Boolean.parseBoolean(context.getConfig().getConfigValue(ADD_RECOVERY_CODES, "false"))) {
            if (!isRecoveryCodesEnabledInAuthenticationFlow(context.getRealm(), context.getSession())) {
                log.info("OTP configured to set up recovery codes, but recovery codes are not enabled in the authentication flows. Skipping the setup of recovery codes.");
            } else if (!context.getRealm().getRequiredActionProviderByAlias(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES.name()).isEnabled()) {
                log.info("OTP configured to set up recovery codes, but recovery codes required action is not enabled. Skipping the setup of recovery codes.");
            } else if (context.getUser().getRequiredActionsStream().noneMatch(s -> s.equals(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES.name()))) {
                if (!context.getUser().credentialManager().isConfiguredFor(RecoveryAuthnCodesCredentialModel.TYPE)) {
                    context.getUser().addRequiredAction(UserModel.RequiredAction.CONFIGURE_RECOVERY_AUTHN_CODES);
                }
            }
        }
    }

    /**
     * Check if recovery codes are enabled in the authentication flow.
     * This is the same logic that is applied in the account console to show if recovery codes can be set up.
     */
    private boolean isRecoveryCodesEnabledInAuthenticationFlow(RealmModel realm, KeycloakSession session) {
        return realm.getAuthenticationFlowsStream()
                .filter(s -> !isFlowEffectivelyDisabled(realm, s))
                .flatMap(flow ->
                        realm.getAuthenticationExecutionsStream(flow.getId())
                                .filter(exe -> Objects.nonNull(exe.getAuthenticator()) && exe.getRequirement() != DISABLED)
                                .map(exe -> (AuthenticatorFactory) session.getKeycloakSessionFactory()
                                        .getProviderFactory(Authenticator.class, exe.getAuthenticator()))
                                .filter(Objects::nonNull)
                                .flatMap(authFact -> Stream.concat(Stream.of(authFact.getReferenceCategory()), authFact.getOptionalReferenceCategories(session).stream()))
                                .filter(Objects::nonNull)
                ).anyMatch(s -> s.equals(RecoveryAuthnCodesCredentialModel.TYPE));
    }

    // Returns true if flow is effectively disabled - either it's execution or some parent execution is disabled
    private boolean isFlowEffectivelyDisabled(RealmModel realm, AuthenticationFlowModel flow) {
        while (!flow.isTopLevel()) {
            AuthenticationExecutionModel flowExecution = realm.getAuthenticationExecutionByFlowId(flow.getId());
            if (flowExecution == null) return false; // Can happen under some corner cases
            if (DISABLED == flowExecution.getRequirement()) return true;
            if (flowExecution.getParentFlow() == null) return false;

            // Check parent flow
            flow = realm.getAuthenticationFlowById(flowExecution.getParentFlow());
            if (flow == null) return false;
        }

        return false;
    }

}
