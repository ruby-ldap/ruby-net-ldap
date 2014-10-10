# Add 'lib' to load path.
require 'test/unit'
require 'net/ldap'
require 'flexmock/test_unit'

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
