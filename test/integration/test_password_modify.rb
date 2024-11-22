require_relative '../test_helper'

class TestPasswordModifyIntegration < LDAPIntegrationTestCase
  # see: https://www.rfc-editor.org/rfc/rfc3062#section-2
  PASSWORD_MODIFY_SYNTAX = Net::BER.compile_syntax(
    application: {},
    universal: {},
    context_specific: { primitive: { 0 => :string } },
  )

  def setup
    super
    @admin_account = { dn: 'cn=admin,dc=example,dc=org', password: 'admin', method: :simple }
    @ldap.authenticate @admin_account[:dn], @admin_account[:password]

    @dn = 'uid=modify-password-user1,ou=People,dc=example,dc=org'

    attrs = {
      objectclass: %w(top inetOrgPerson organizationalPerson person),
      uid: 'modify-password-user1',
      cn: 'modify-password-user1',
      sn: 'modify-password-user1',
      mail: 'modify-password-user1@rubyldap.com',
      userPassword: 'admin',
    }
    unless @ldap.search(base: @dn, scope: Net::LDAP::SearchScope_BaseObject)
      assert @ldap.add(dn: @dn, attributes: attrs), @ldap.get_operation_result.inspect
    end
    assert @ldap.search(base: @dn, scope: Net::LDAP::SearchScope_BaseObject)

    @auth = {
      method: :simple,
      username: @dn,
      password: 'admin',
    }
  end

  def test_password_modify
    assert @ldap.password_modify(dn: @dn,
                                 auth: @auth,
                                 old_password: 'admin',
                                 new_password: 'passworD2')

    assert @ldap.get_operation_result.extended_response.nil?,
           'Should not have generated a new password'

    refute @ldap.bind(username: @dn, password: 'admin', method: :simple),
           'Old password should no longer be valid'

    assert @ldap.bind(username: @dn, password: 'passworD2', method: :simple),
           'New password should be valid'
  end

  def test_password_modify_generate
    assert @ldap.password_modify(dn: @dn,
                                 auth: @auth,
                                 old_password: 'admin')

    passwd_modify_response_value = @ldap.get_operation_result.extended_response
    seq = Net::BER::BerIdentifiedArray.new
    sio = StringIO.new(passwd_modify_response_value)
    until (e = sio.read_ber(PASSWORD_MODIFY_SYNTAX)).nil?
      seq << e
    end
    generated_password = seq[0][0]

    assert generated_password, 'Should have generated a password'

    refute @ldap.bind(username: @dn, password: 'admin', method: :simple),
           'Old password should no longer be valid'

    assert @ldap.bind(username: @dn, password: generated_password, method: :simple),
           'New password should be valid'
  end

  def test_password_modify_generate_no_old_password
    assert @ldap.password_modify(dn: @dn,
                                 auth: @auth)

    passwd_modify_response_value = @ldap.get_operation_result.extended_response
    seq = Net::BER::BerIdentifiedArray.new
    sio = StringIO.new(passwd_modify_response_value)
    until (e = sio.read_ber(PASSWORD_MODIFY_SYNTAX)).nil?
      seq << e
    end
    generated_password = seq[0][0]
    assert generated_password, 'Should have generated a password'

    refute @ldap.bind(username: @dn, password: 'admin', method: :simple),
           'Old password should no longer be valid'

    assert @ldap.bind(username: @dn, password: generated_password, method: :simple),
           'New password should be valid'
  end

  def test_password_modify_overwrite_old_password
    assert @ldap.password_modify(dn: @dn,
                                 auth: @admin_account,
                                 new_password: 'passworD3')

    refute @ldap.bind(username: @dn, password: 'admin', method: :simple),
           'Old password should no longer be valid'

    assert @ldap.bind(username: @dn, password: 'passworD3', method: :simple),
           'New password should be valid'
  end

  def teardown
    @ldap.delete dn: @dn
  end
end
