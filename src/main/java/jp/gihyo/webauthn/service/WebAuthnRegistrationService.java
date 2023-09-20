package jp.gihyo.webauthn.service;

import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.SupportedExtensionsExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import jp.gihyo.webauthn.entity.Credential;
import jp.gihyo.webauthn.entity.User;
import jp.gihyo.webauthn.repository.CredentialRepository;
import jp.gihyo.webauthn.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class WebAuthnRegistrationService {

  private final UserRepository userRepository;
  private final CredentialRepository credentialRepository;

  public WebAuthnRegistrationService(UserRepository userRepository, CredentialRepository credentialRepository) {
    this.userRepository = userRepository;
    this.credentialRepository = credentialRepository;
  }

  public PublicKeyCredentialCreationOptions creationOptions(User user) {

    // rp - 中間車攻撃を回避するRPサーバー情報
    var rpId = "localhost";
    var rpName = "Gihyo Relying Party";
    var rp = new PublicKeyCredentialRpEntity(
      rpId, rpName
    );

    // user - ユーザー情報
    var userId = user.getId();
    var userName = user.getEmail();
    var userDisplayName = "";
    var userInfo = new PublicKeyCredentialUserEntity(userId, userName, userDisplayName);

    // challenge - リプレイ攻撃を回避する乱数
    var challenge = new DefaultChallenge();

    // pubKeyCredParams - クレデンシャル生成方法の要求事項
    var es256 = new PublicKeyCredentialParameters(
      PublicKeyCredentialType.PUBLIC_KEY,
      COSEAlgorithmIdentifier.ES256
    );
    var rs256 = new PublicKeyCredentialParameters(
      PublicKeyCredentialType.PUBLIC_KEY,
      COSEAlgorithmIdentifier.RS256
    );
    var publicKeyCredParams = List.of(es256, rs256);

    // timeout(milli sec)
    var timeout = 120000L;

    // excludeCredentials - 同一認証器の登録制限
    var credentials = credentialRepository.finds(user.getId());
    var excludeCredentials =
      credentials.
        stream().
        map(credential ->
          new PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential.getCredentialId(),
            Set.of()
          )
        ).
        collect(Collectors.toList());

    // authenticationSelection - 認証器の要求事項
    var authenticatorAttachment =
      AuthenticatorAttachment.PLATFORM;
    var requireResidentKey = false;
    var userVerification =
      UserVerificationRequirement.REQUIRED;
    var authenticatorSelection =
      new AuthenticatorSelectionCriteria(
        authenticatorAttachment,
        requireResidentKey,
        userVerification
      );

    // attestation - 認証器のアテステーション
//    var attestation = AttestationConveyancePreference.NONE;
    var attestation = AttestationConveyancePreference.DIRECT;

    // extensions - 登録の拡張機能
    var extensionsMap = new HashMap<String, RegistrationExtensionClientInput>();
    // 認証器がWebAuthnのどの拡張機能に対応しているのかを調べる拡張機能
    extensionsMap.put(SupportedExtensionsExtensionClientInput.ID, new SupportedExtensionsExtensionClientInput(true));
    var extensions = new AuthenticationExtensionsClientInputs<>(extensionsMap);

    // 公開鍵クレデンシャル生成API
    return new PublicKeyCredentialCreationOptions(
      rp,
      userInfo,
      challenge,
      publicKeyCredParams,
      timeout,
      excludeCredentials,
      authenticatorSelection,
      attestation,
      extensions
    );
  }

  public User findOrElseCreate(String email, String displayName) {
    return userRepository.find(email)
      .orElseGet(() -> createUser(email, displayName));
  }

  private User createUser(String email, String displayName) {

    var userId = new byte[32];
    new SecureRandom().nextBytes(userId);

    var user = new User();
    user.setId(userId);
    user.setEmail(email);
    user.setDisplayName(displayName);

    return user;
  }

  public void creationFinish(
    User user,
    Challenge challenge,
    byte[] clientJSON,
    byte[] attestationObject) {

    // originの検証 - 中間者攻撃耐性
    var origin = Origin.create("http://localhost:8000");

    // rpIdHashの検証 - 中間者攻撃耐性
    var rpId = "localhost";

    // challengeの検証 - リプレイ攻撃耐性
    var challengeBase64 = new DefaultChallenge(Base64.getEncoder().encode(challenge.getValue()));

    byte[] tokenBindingId = null;

    var serverProperty = new ServerProperty(
      origin,
      rpId,
      challengeBase64,
      tokenBindingId);

    // flagsの検証 - ユーザーの検証（他要素認証）
    var userVerificationRequired = true;

    var registrationContext = new WebAuthnRegistrationContext(
      clientJSON,
      attestationObject,
      serverProperty,
      userVerificationRequired);

    var validator =
      WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();

    // clientDataJSONの検証
    // attestationObjectの検証
    var response = validator.validate(registrationContext);

    // DBに保存する公開鍵クレデンシャルを取得
    var credentialId = response
        .getAttestationObject()
        .getAuthenticatorData()
        .getAttestedCredentialData()
        .getCredentialId();

    // DBに保存する公開鍵クレデンシャルにアテステーションも含める
    var authenticator = new AuthenticatorImpl(
        response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
        response.getAttestationObject().getAttestationStatement(),
        response.getAttestationObject().getAuthenticatorData().getSignCount(),
        Set.of(),
        response.getRegistrationExtensionsClientOutputs(),
        Map.of());

    var signatureCounter = response
        .getAttestationObject()
        .getAuthenticatorData()
        .getSignCount();

    // ユーザ作成
    if (userRepository.find(user.getEmail()).isEmpty()) {
      userRepository.insert(user);
    }

    // 公開鍵クレデンシャルを保存用にバイナリ化
    //   ※サンプルコードでは、DBに保存する公開鍵クレデンシャルにアテステーションも含める
    var authenticatorBin = new CborConverter().writeValueAsBytes(authenticator);

    // 公開鍵クレデンシャルの保存
    var credential = new Credential();
    credential.setCredentialId(credentialId);
    credential.setUserId(user.getId());
    credential.setPublicKey(authenticatorBin);
    credential.setSignatureCounter(signatureCounter);

    credentialRepository.insert(credential);
  }
}
