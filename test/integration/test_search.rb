require_relative '../test_helper'

class TestSearchIntegration < LDAPIntegrationTestCase
  def test_search
    entries = []

    result = @ldap.search(base: "dc=rubyldap,dc=com") do |entry|
      assert_kind_of Net::LDAP::Entry, entry
      entries << entry
    end

    refute entries.empty?
    assert_equal entries, result
  end

  def test_search_without_result
    entries = []

    result = @ldap.search(base: "dc=rubyldap,dc=com", return_result: false) do |entry|
      assert_kind_of Net::LDAP::Entry, entry
      entries << entry
    end

    assert result
    refute_equal entries, result
  end

  def test_search_filter_string
    entries = @ldap.search(base: "dc=rubyldap,dc=com", filter: "(uid=user1)")
    assert_equal 1, entries.size
  end

  def test_search_filter_object
    filter = Net::LDAP::Filter.eq("uid", "user1") | Net::LDAP::Filter.eq("uid", "user2")
    entries = @ldap.search(base: "dc=rubyldap,dc=com", filter: filter)
    assert_equal 2, entries.size
  end

  def test_search_constrained_attributes
    entry = @ldap.search(base: "uid=user1,ou=People,dc=rubyldap,dc=com", attributes: ["cn", "sn"]).first
    assert_equal [:cn, :dn, :sn], entry.attribute_names.sort  # :dn is always included
    assert_empty entry[:mail]
  end

  # http://tools.ietf.org/html/rfc4511#section-4.5.1.4
  def test_search_size
    skip "search treats sizeLimitExceeded response as failure"

    entries = @ldap.search(base: "ou=People,dc=rubyldap,dc=com", size: 2)

    assert_equal 2, entries.size
  end

  # See: test_search_size for what *should* work.
  #
  # This tests the currently broken behavior where searches are reported as
  # failed when the size limit has been reached. This is broken since the
  # sizeLimit parameter defines how many results to send back, and will result
  # in a sizeLimitExceeded result in cases where there are more results than
  # returned; not an error case, but also not a result code that is categorized
  # as a non-error result (http://tools.ietf.org/html/rfc4511#appendix-A.1).
  # The practical choice is to treat sizeLimitExceeded (and timeLimitExceeded)
  # as successful search terminating messages.
  def test_search_size_broken
    entries = []

    returned = @ldap.search(base: "ou=People,dc=rubyldap,dc=com", size: 2) do |entry|
      entries << entry.dn
    end
    refute returned

    # reported as an "error" of sizeLimitExceeded
    result = @ldap.get_operation_result
    assert_equal 4, result.code
    assert_equal Net::LDAP::ResultStrings[4], result.message

    # received the right number of results
    assert_equal 2, entries.size
  end

  def test_search_attributes_only
    entry = @ldap.search(base: "uid=user1,ou=People,dc=rubyldap,dc=com", attributes_only: true).first

    assert_empty entry[:cn], "unexpected attribute value: #{entry[:cn]}"
  end
end
