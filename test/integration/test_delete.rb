require_relative '../test_helper'

class TestDeleteIntegration < LDAPIntegrationTestCase
  def setup
    super
    @dn = "uid=delete-user1,ou=People,dc=example,dc=org"

    attrs = {
      objectclass: %w(top inetOrgPerson organizationalPerson person),
      uid:  "delete-user1",
      cn:   "delete-user1",
      sn:   "delete-user1",
      mail: "delete-user1@rubyldap.com",
    }
    unless @ldap.search(base: @dn, scope: Net::LDAP::SearchScope_BaseObject)
      assert @ldap.add(dn: @dn, attributes: attrs), @ldap.get_operation_result.inspect
    end
    assert @ldap.search(base: @dn, scope: Net::LDAP::SearchScope_BaseObject)

    @parent_dn = "uid=parent,ou=People,dc=example,dc=org"
    parent_attrs = {
      objectclass: %w(top inetOrgPerson organizationalPerson person),
      uid:  "parent",
      cn:   "parent",
      sn:   "parent",
      mail: "parent@rubyldap.com",
    }
    @child_dn = "uid=child,uid=parent,ou=People,dc=example,dc=org"
    child_attrs = {
      objectclass: %w(top inetOrgPerson organizationalPerson person),
      uid:  "child",
      cn:   "child",
      sn:   "child",
      mail: "child@rubyldap.com",
    }
    unless @ldap.search(base: @parent_dn, scope: Net::LDAP::SearchScope_BaseObject)
      assert @ldap.add(dn: @parent_dn, attributes: parent_attrs), @ldap.get_operation_result.inspect
      assert @ldap.add(dn: @child_dn, attributes: child_attrs), @ldap.get_operation_result.inspect
    end
    assert @ldap.search(base: @parent_dn, scope: Net::LDAP::SearchScope_BaseObject)
    assert @ldap.search(base: @child_dn, scope: Net::LDAP::SearchScope_BaseObject)
  end

  def test_delete
    assert @ldap.delete(dn: @dn), @ldap.get_operation_result.inspect
    refute @ldap.search(base: @dn, scope: Net::LDAP::SearchScope_BaseObject)

    result = @ldap.get_operation_result
    assert_equal Net::LDAP::ResultCodeNoSuchObject, result.code
    assert_equal Net::LDAP::ResultStrings[Net::LDAP::ResultCodeNoSuchObject], result.message
  end

  def test_delete_tree
    assert @ldap.delete_tree(dn: @parent_dn), @ldap.get_operation_result.inspect
    refute @ldap.search(base: @parent_dn, scope: Net::LDAP::SearchScope_BaseObject)
    refute @ldap.search(base: @child_dn, scope: Net::LDAP::SearchScope_BaseObject)

    result = @ldap.get_operation_result
    assert_equal Net::LDAP::ResultCodeNoSuchObject, result.code
    assert_equal Net::LDAP::ResultStrings[Net::LDAP::ResultCodeNoSuchObject], result.message
  end
end
