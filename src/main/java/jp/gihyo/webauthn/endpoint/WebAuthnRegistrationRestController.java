package jp.gihyo.webauthn.endpoint;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.client.challenge.Challenge;
import jp.gihyo.webauthn.entity.User;
import jp.gihyo.webauthn.service.WebAuthnRegistrationService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;

public class WebAuthnRegistrationRestController {

  private final WebAuthnRegistrationService webAuthnService;

  public WebAuthnRegistrationRestController(WebAuthnRegistrationService webAuthnService) {
    this.webAuthnService = webAuthnService;
  }

  // POST /attestation/options のJSONパラメーター
  private static class AttestationOptionsParam {
    public String email;
    public String displayName;
  }

  // POST /attestation/options のエンドポイント
  @PostMapping(value = "/attestation/options")
  public PublicKeyCredentialCreationOptions postAttestationOptions(
    @RequestBody AttestationOptionsParam params,
    HttpServletRequest httpRequest
  ) {
    var user = webAuthnService.findOrElseCreate(params.email, params.displayName);
    var options = webAuthnService.creationOptions(user);

    // チャレンジをHTTPセッションに一時保存
    var session = httpRequest.getSession();
    session.setAttribute("attestationChallenge", options.getChallenge());
    session.setAttribute("attestationUser", user);

    return options;
  }

  // POST /attestations/result のJSONパラメーター
  private static class AttestationResultParam {
    public byte[] clientDataJSON;
    public byte[] attestationObject;
  }

  // POST /attestation/result のエンドポイント
  @PostMapping(value = "/attestation/result")
  public void postAttestationResult(
    @RequestBody AttestationResultParam params,
    HttpServletRequest httpRequest
  ) throws JsonProcessingException {
    // HTTPセッションからチャレンジを取得
    var httpSession = httpRequest.getSession();
    var challenge = (Challenge)httpSession.getAttribute("attestationChallenge");
    var user = (User)httpSession.getAttribute("attestationUser");

    // 公開鍵クレデンシャルの検証と保存
    webAuthnService.creationFinish(
      user,
      challenge,
      params.clientDataJSON,
      params.attestationObject
    );
  }
}
