require_relative 'test_helper'

if !INTEGRATION
  puts "Skipping integration tests..."
else
  class TestLDAPInstrumentation < Test::Unit::TestCase
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
      assert @ldap.bind(method: :simple, username: "user1", password: "passworD1")
    end

    def test_bind_success_anonymous
      assert @ldap.bind(method: :simple, username: "user1", password: "")
    end

    def test_bind_fail
      refute @ldap.bind(method: :simple, username: "user1", password: "not my password")
    end
  end
end
