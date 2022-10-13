package ee.cyber.cdoc20.server;

import lombok.Value;

import java.security.KeyPair;

import ee.cyber.cdoc20.server.conf.LoadedKeyStore;
import ee.cyber.cdoc20.server.dto.EccDetailsRequest;

/**
 * Generated capsule
 */
@Value
public class GeneratedCapsule {
    // keystore with client certificate used by this user
    LoadedKeyStore keyStore;
    // the generated ephemeral key pair
    KeyPair senderKeyPair;
    // the request payload for the server
    EccDetailsRequest request;
}
