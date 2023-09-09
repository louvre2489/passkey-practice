package jp.gihyo.webauthn.repository;

import jp.gihyo.webauthn.entity.User;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.util.Optional;

@Repository
public class UserRepository {

  private final NamedParameterJdbcOperations jdbc;
  private final SimpleJdbcInsert insertUser;

  public UserRepository(NamedParameterJdbcOperations jdbc, DataSource dataSource) {
    this.jdbc = jdbc;
    this.insertUser = new SimpleJdbcInsert(dataSource).withTableName("user");
  }

  public Optional<User> find(String email) {
    var sql = "SELECT * FROM user WHERE email =:email";

    try {
      var user = jdbc.queryForObject(
        sql,
        new MapSqlParameterSource().addValue("email", email),
        new BeanPropertyRowMapper<>(User.class)
      );

      return Optional.of(user);
    } catch (EmptyResultDataAccessException ignore) {
      return Optional.empty();
    }
  }
}
