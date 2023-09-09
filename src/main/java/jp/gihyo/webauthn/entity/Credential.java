package jp.gihyo.webauthn.entity;

public class Credential {
  private byte[] credentialId;
  private byte[] userId;
  private byte[] publicKey;
  private long signatureCounter;

  public byte[] getCredentialId() {
    return credentialId;
  }

  public void setCredentialId(final byte[] credentialId) {
    this.credentialId = credentialId;
  }

  public byte[] getUserId() {
    return userId;
  }

  public void setUserId(final byte[] userId) {
    this.userId = userId;
  }

  public byte[] getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(final byte[] publicKey) {
    this.publicKey = publicKey;
  }

  public long getSignatureCounter() {
    return signatureCounter;
  }

  public void setSignatureCounter(final long signatureCounter) {
    this.signatureCounter = signatureCounter;
  }
}