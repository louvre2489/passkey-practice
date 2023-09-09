package jp.gihyo.webauthn.repository;

import jp.gihyo.webauthn.entity.Credential;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.util.List;

@Repository
public class CredentialRepository {

  private final NamedParameterJdbcOperations jdbc;

  // ※サンプルコードでは、INSERTを簡略化
  //   https://docs.spring.io/spring/docs/current/spring-framework-reference/data-access.html#jdbc-simple-jdbc
  private final SimpleJdbcInsert insertCredential;

  public CredentialRepository(NamedParameterJdbcOperations jdbc, DataSource dataSource) {
    this.jdbc = jdbc;
    this.insertCredential = new SimpleJdbcInsert(dataSource).withTableName("credential");
  }

  public List<Credential> finds(byte[] userId) {
    var sql = "SELECT * FROM credential WHERE user_id =:userId";

    return jdbc.query(
      sql,
      new MapSqlParameterSource().addValue("userId", userId),
      new BeanPropertyRowMapper<>(Credential.class)
    );
  }
}
