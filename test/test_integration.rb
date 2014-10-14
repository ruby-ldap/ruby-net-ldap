require_relative 'test_helper'

if !INTEGRATION
  puts "Skipping integration tests..."
else
  class TestLDAPIntegration < Test::Unit::TestCase
    def setup
      @service = MockInstrumentationService.new
      @ldap = Net::LDAP.new \
        host:           'localhost',
        port:           389,
        admin_user:     'uid=admin,dc=rubyldap,dc=com',
        admin_password: 'passworD1',
        search_domains: %w(dc=rubyldap,dc=com),
        uid:            'uid',
        instrumentation_service: @service
    end

    def test_bind_success
      assert @ldap.bind(method: :simple, username: "uid=user1,ou=People,dc=rubyldap,dc=com", password: "passworD1"), @ldap.get_operation_result.inspect
    end

    def test_bind_anonymous_fail
      refute @ldap.bind(method: :simple, username: "uid=user1,ou=People,dc=rubyldap,dc=com", password: ""), @ldap.get_operation_result.inspect

      result = @ldap.get_operation_result
      assert_equal 53, result.code
      assert_equal "Unwilling to perform", result.message
      assert_equal "unauthenticated bind (DN with no password) disallowed",
        result.error_message
      assert_equal "", result.matched_dn
    end

    def test_bind_fail
      refute @ldap.bind(method: :simple, username: "uid=user1,ou=People,dc=rubyldap,dc=com", password: "not my password"), @ldap.get_operation_result.inspect
    end
  end
end
