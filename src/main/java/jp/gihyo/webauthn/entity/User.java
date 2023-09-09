package jp.gihyo.webauthn.entity;

public class User {
  private byte[] id;
  private String email;
  private String displayName;

  public byte[] getId() {
    return id;
  }

  public void setId(final byte[] id) {
    this.id = id;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(final String email) {
    this.email = email;
  }

  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(final String displayName) {
    this.displayName = displayName;
  }
}
