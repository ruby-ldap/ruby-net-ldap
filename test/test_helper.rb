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
