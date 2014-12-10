require_relative '../test_helper'

class TestBindIntegration < LDAPIntegrationTestCase
  def test_bind_success
    assert @ldap.bind(method: :simple, username: "uid=user1,ou=People,dc=rubyldap,dc=com", password: "passworD1"), @ldap.get_operation_result.inspect
  end

  def test_bind_anonymous_fail
    refute @ldap.bind(method: :simple, username: "uid=user1,ou=People,dc=rubyldap,dc=com", password: ""), @ldap.get_operation_result.inspect

    result = @ldap.get_operation_result
    assert_equal Net::LDAP::ResultCodeUnwillingToPerform, result.code
    assert_equal Net::LDAP::ResultStrings[Net::LDAP::ResultCodeUnwillingToPerform], result.message
    assert_equal "unauthenticated bind (DN with no password) disallowed",
      result.error_message
    assert_equal "", result.matched_dn
  end

  def test_bind_fail
    refute @ldap.bind(method: :simple, username: "uid=user1,ou=People,dc=rubyldap,dc=com", password: "not my password"), @ldap.get_operation_result.inspect
  end

  def test_bind_tls_with_cafile
    tls_options = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge(:ca_file => CA_FILE)
    @ldap.encryption(method: :start_tls, tls_options: tls_options)
    assert @ldap.bind(method: :simple, username: "uid=user1,ou=People,dc=rubyldap,dc=com", password: "passworD1"), @ldap.get_operation_result.inspect
  end

  def test_bind_tls_with_verify_none
    tls_options = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge(:verify_mode => OpenSSL::SSL::VERIFY_NONE)
    @ldap.encryption(method: :start_tls, tls_options: tls_options)
    assert @ldap.bind(method: :simple, username: "uid=user1,ou=People,dc=rubyldap,dc=com", password: "passworD1"), @ldap.get_operation_result.inspect
  end
end
