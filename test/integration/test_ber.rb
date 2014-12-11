require_relative '../test_helper'

class TestBERIntegration < LDAPIntegrationTestCase
  # Test whether the TRUE boolean value is encoded correctly by performing a
  # search operation.
  def test_true_ber_encoding
    # request these attrs to simplify test; use symbols to match Entry#attribute_names
    attrs = [:dn, :uid, :cn, :mail]

    assert types_entry = @ldap.search(
      base: "dc=rubyldap,dc=com",
      filter: "(uid=user1)",
      size: 1,
      attributes: attrs,
      attributes_only: true
    ).first

    # matches attributes we requested
    assert_equal attrs, types_entry.attribute_names

    # assert values are empty
    types_entry.each do |name, values|
      next if name == :dn
      assert values.empty?
    end

    assert_includes Net::LDAP::ResultCodesSearchSuccess,
      @ldap.get_operation_result.code, "should be a successful search operation"
  end

  def test_ber_encoding_message_id_greater_than_128
    @ldap.open do |client|
      256.times {
        entries = client.search \
          base: "dc=rubyldap,dc=com",
          filter: "(uid=user1)",
          size: 1
        assert_equal "uid=user1,ou=People,dc=rubyldap,dc=com", entries.first.dn
      }
      message_id = client.instance_variable_get('@open_connection').instance_variable_get('@msgid')
      assert_operator message_id, :>, 256  # includes non-search messages
    end
  end
end
