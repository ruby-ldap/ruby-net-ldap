require_relative '../test_helper'

class TestBindIntegration < LDAPIntegrationTestCase
  def test_binds_without_open
    events = @service.subscribe "bind.net_ldap_connection"

    @ldap.search(filter: "uid=user1", base: "ou=People,dc=rubyldap,dc=com", ignore_server_caps: true)
    @ldap.search(filter: "uid=user1", base: "ou=People,dc=rubyldap,dc=com", ignore_server_caps: true)

    assert_equal 2, events.size
  end

  def test_binds_with_open
    events = @service.subscribe "bind.net_ldap_connection"

    @ldap.open do
      @ldap.search(filter: "uid=user1", base: "ou=People,dc=rubyldap,dc=com", ignore_server_caps: true)
      @ldap.search(filter: "uid=user1", base: "ou=People,dc=rubyldap,dc=com", ignore_server_caps: true)
    end

    assert_equal 1, events.size
  end
end
