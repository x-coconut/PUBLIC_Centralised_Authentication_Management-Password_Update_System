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

import org.keycloak.common.util.Time;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;

import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.MessageProperties;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.BuiltinExchangeType;
import com.rabbitmq.client.Channel;

import ecies.Ecies;

import java.math.BigInteger;

import java.util.Base64;
import java.util.Map;

import org.json.JSONObject;

public class PasswordInterceptorProvider extends PasswordCredentialProvider {

    public PasswordInterceptorProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    public boolean createCredential(RealmModel realm, UserModel user, String password) {

        // source code from
        // https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/credential/PasswordCredentialProvider.java

        PasswordPolicy policy = realm.getPasswordPolicy();

        PolicyError error = session.getProvider(PasswordPolicyManagerProvider.class).validate(realm, user, password);
        if (error != null)
            throw new ModelException(error.getMessage(), error.getParameters());

        PasswordHashProvider hash = getHashProvider(policy);
        if (hash == null) {
            return false;
        }
        try {
            PasswordCredentialModel credentialModel = hash.encodedCredential(password, policy.getHashIterations());
            credentialModel.setCreatedDate(Time.currentTimeMillis());
            createCredential(realm, user, credentialModel);

            // ---------- CUSTOM LOGIC GOES HERE ----------

            // get public key
            try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                HttpGet request = new HttpGet("http://192.168.43.128:5000"); // UPDATE TO IP ADDRESS WHERE KEYS ARE
                                                                             // PRODUCED

                try (CloseableHttpResponse response = httpClient.execute(request)) {
                    String public_der_b64 = EntityUtils.toString(response.getEntity());

                    // encrypt password
                    String encryptedPassword = encrypt(password, public_der_b64);
                    if (encryptedPassword != "") { // empty string is returned if something went wrong during encryption

                        // Create JSON message
                        JSONObject json = new JSONObject();
                        json.put("username", user.getUsername());
                        json.put("encryptedPassword", encryptedPassword);
                        json.put("allowedIPs", user.getAttributes().get("allowedIPs")); // UPDATE TO NAME OF CUSTOM
                                                                                        // ATTRIBUTE
                        String message = json.toString();

                        // RabbitMQ guide - https://www.rabbitmq.com/tutorials/tutorial-one-java

                        // Setup connection parameters for RabbitMQ
                        ConnectionFactory factory = new ConnectionFactory();
                        factory.setHost("192.168.43.128"); // UPDATE THIS TO IP FOR RABBITMQ SERVER
                        factory.setPort(5672);
                        factory.setUsername("guest"); // UPDATE TO RABBITMQ USERNAME
                        factory.setPassword("guest"); // UPDATE TO RABBITMQ PASSWORD
                        String QueueName = "main_queue";

                        // Establish a connection to RabbitMQ
                        try (Connection connection = factory.newConnection();
                                Channel channel = connection.createChannel()) {

                            setup_queues_and_exchange(channel);

                            // Send message to main_queue
                            channel.basicPublish("", QueueName, MessageProperties.PERSISTENT_TEXT_PLAIN,
                                    message.getBytes("UTF-8"));
                        }
                    } else {
                        throw new RuntimeException("Error during password encryption");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            // ---------- END OF CUSTOM LOGIC ----------

        } catch (Throwable t) {
            throw new ModelException(t.getMessage(), t);
        }
        return true;
    }

    // encrypts the user's password
    static String encrypt(String password, String public_der_b64) {

        try {

            // Decode the Base64-encoded DER back to DER
            byte[] public_der = Base64.getDecoder().decode(public_der_b64);

            // Convert to a publicKey object
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(public_der);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Convert to an EC publicKey object
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            ECPoint point = ecPublicKey.getW();

            // Manually convert to compressed format - the hex bytes
            BigInteger x = point.getAffineX();
            BigInteger y = point.getAffineY();
            int pointLength = (x.bitLength() + 7) / 8;
            byte[] public_bytes = new byte[pointLength + 1];
            public_bytes[0] = (byte) (y.testBit(0) ? 0x03 : 0x02);
            byte[] xBytes = x.toByteArray();
            // remove the 2s complement leading 0 - if there is one
            if (xBytes.length > pointLength) {
                if (xBytes[0] == 0) {
                    // Remove leading zero byte
                    byte[] temp = new byte[xBytes.length - 1];
                    System.arraycopy(xBytes, 1, temp, 0, temp.length);
                    xBytes = temp;
                }
            }
            System.arraycopy(xBytes, 0, public_bytes, 1, xBytes.length);

            // convert byte array to string of hex
            StringBuilder sb = new StringBuilder();
            for (byte b : public_bytes) {
                // Convert each byte to its hex representation and append it
                sb.append(String.format("%02X", b));
            }
            String public_hex = sb.toString();

            // Encrypt the plaintext using the public key
            String encrypted_hex = Ecies.encrypt(public_hex, password);

            // Convert hex string to byte array
            int len = encrypted_hex.length();
            byte[] encrypted_bytes = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                encrypted_bytes[i / 2] = (byte) ((Character.digit(encrypted_hex.charAt(i), 16) << 4)
                        + Character.digit(encrypted_hex.charAt(i + 1), 16));
            }

            // Encode byte array to Base64
            String encrypted_b64 = Base64.getEncoder().encodeToString(encrypted_bytes);

            return encrypted_b64;

        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    static void setup_queues_and_exchange(Channel channel) throws Exception {

        // they are only created if they don't already exist
        // all declared as durable - so they aren't deleted if RabbitMQ server goes down

        // declare exchange
        channel.exchangeDeclare("dlx_exchange", BuiltinExchangeType.DIRECT, true);

        // declare the queues
        channel.queueDeclare("main_queue", true, false, false, Map.of(
                "x-dead-letter-exchange", "dlx_exchange",
                "x-dead-letter-routing-key", "waiting_5_min"));

        channel.queueDeclare("waiting_5_min", true, false, false, Map.of(
                "x-message-ttl", 300000, // TTL of 5 min
                "x-dead-letter-exchange", "dlx_exchange",
                "x-dead-letter-routing-key", "retry"));

        channel.queueDeclare("waiting_25_min", true, false, false, Map.of(
                "x-message-ttl", 1500000, // TTL of 25 min
                "x-dead-letter-exchange", "dlx_exchange",
                "x-dead-letter-routing-key", "retry"));

        channel.queueDeclare("waiting_125_min", true, false, false, Map.of(
                "x-message-ttl", 7500000, // TTL of 125 min (2h 5m)
                "x-dead-letter-exchange", "dlx_exchange",
                "x-dead-letter-routing-key", "retry"));

        channel.queueDeclare("waiting_625_min", true, false, false, Map.of(
                "x-message-ttl", 37500000, // TTL of 625 min (10h 25m)
                "x-dead-letter-exchange", "dlx_exchange",
                "x-dead-letter-routing-key", "retry"));

        channel.queueDeclare("waiting_3125_min", true, false, false, Map.of(
                "x-message-ttl", 187500000, // TTL of 3125 min (2d 4h 5m)
                "x-dead-letter-exchange", "dlx_exchange",
                "x-dead-letter-routing-key", "retry"));

        channel.queueDeclare("retry", true, false, false, null);
        channel.queueDeclare("failed_messages", true, false, false, null);

        // bind queues to exchange
        channel.queueBind("waiting_5_min", "dlx_exchange", "waiting_5_min");
        channel.queueBind("waiting_25_min", "dlx_exchange", "waiting_25_min");
        channel.queueBind("waiting_125_min", "dlx_exchange", "waiting_125_min");
        channel.queueBind("waiting_625_min", "dlx_exchange", "waiting_625_min");
        channel.queueBind("waiting_3125_min", "dlx_exchange", "waiting_3125_min");
        channel.queueBind("retry", "dlx_exchange", "retry");
        channel.queueBind("failed_messages", "dlx_exchange", "failed_messages");
    }

}
