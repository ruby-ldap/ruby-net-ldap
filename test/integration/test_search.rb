require_relative '../test_helper'

class TestSearchIntegration < LDAPIntegrationTestCase
  def test_search
    entries = []

    result = @ldap.search(filter: "(uid=user1)", base: "dc=rubyldap,dc=com") do |entry|
      assert_kind_of Net::LDAP::Entry, entry
      entries << entry
    end

    refute entries.empty?
    assert_equal entries, result
  end

  def test_search_without_result
    entries = []

    result = @ldap.search(filter: "(uid=user1)", base: "dc=rubyldap,dc=com", return_result: false) do |entry|
      assert_kind_of Net::LDAP::Entry, entry
      entries << entry
    end

    assert result
    refute_equal entries, result
  end

  def test_search_timeout
    events = @service.subscribe "search.net_ldap_connection"

    result = @ldap.search(base: "dc=rubyldap,dc=com", time: 5)

    payload, result = events.pop
    assert_equal 5, payload[:time]
    assert_equal entries, result
  end

  def test_search_with_size
    entries = []

    result = @ldap.search(filter: "(uid=user1)", base: "dc=rubyldap,dc=com", size: 1) do |entry|
      assert_kind_of Net::LDAP::Entry, entry
      entries << entry
    end

    refute entries.empty?
    assert_equal entries, result
  end
end
