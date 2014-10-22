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

  def test_nested_search_without_open
    entries = []
    nested_entry = nil

    @ldap.search(filter: "(|(uid=user1)(uid=user2))", base: "ou=People,dc=rubyldap,dc=com") do |entry|
      entries << entry.uid.first
      nested_entry ||= @ldap.search(filter: "uid=user3", base: "ou=People,dc=rubyldap,dc=com").first
    end

    assert_equal "user3", nested_entry.uid.first
    assert_equal %w(user1 user2), entries
  end

  def test_nested_search_with_open
    entries = []
    nested_entry = nil

    @ldap.open do
      @ldap.search(filter: "(|(uid=user1)(uid=user2))", base: "ou=People,dc=rubyldap,dc=com") do |entry|
        entries << entry.uid.first
        nested_entry ||= @ldap.search(filter: "uid=user3", base: "ou=People,dc=rubyldap,dc=com").first
      end
    end

    assert_equal "user3", nested_entry.uid.first
    assert_equal %w(user1 user2), entries
  end
end
