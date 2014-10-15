# Add 'lib' to load path.
require 'test/unit'
require 'net/ldap'
require 'flexmock/test_unit'

# Whether integration tests should be run.
INTEGRATION = ENV.fetch("INTEGRATION", "skip") != "skip"

if RUBY_VERSION < "2.0"
  class String
    def b
      self
    end
  end
end

class MockInstrumentationService
  def initialize
    @events = {}
  end

  def instrument(event, payload)
    result = yield(payload)
    @events[event] ||= []
    @events[event] << [payload, result]
    result
  end

  def subscribe(event)
    @events[event] ||= []
    @events[event]
  end
end

class LDAPIntegrationTestCase < Test::Unit::TestCase
  # If integration tests aren't enabled, noop these tests.
  if !INTEGRATION
    def run(*)
      self
    end
  end

  def setup
    @service = MockInstrumentationService.new
    @ldap = Net::LDAP.new \
      host:           ENV.fetch('INTEGRATION_HOST', 'localhost'),
      port:           389,
      admin_user:     'uid=admin,dc=rubyldap,dc=com',
      admin_password: 'passworD1',
      search_domains: %w(dc=rubyldap,dc=com),
      uid:            'uid',
      instrumentation_service: @service
  end
end
