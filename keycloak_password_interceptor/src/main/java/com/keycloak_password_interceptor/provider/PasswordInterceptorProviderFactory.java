// Copyright 2024 @x-coconut

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.keycloak_password_interceptor.provider;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class PasswordInterceptorProviderFactory implements CredentialProviderFactory<PasswordInterceptorProvider> {

    public static final String PROVIDER_ID = "keycloak-password"; // same as ID in Keycloak sourcecode -
                                                                  // https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/credential/PasswordCredentialProviderFactory.java

    @Override
    public PasswordInterceptorProvider create(KeycloakSession session) {
        return new PasswordInterceptorProvider(session);
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // Initialization configuration
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post initialization logic
    }

    @Override
    public void close() {
        // Close logic
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
