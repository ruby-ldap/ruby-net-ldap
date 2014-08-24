require 'net/ldap'

RSpec.configure do |config|
  config.mock_with :flexmock

  def raw_string(s)
    # Conveniently, String#b only needs to be called when it exists
    s.respond_to?(:b) ? s.b : s
  end
end

class MockInstrumentationService
  attr_reader :events

  def initialize
    @events = []
  end

  def instrument(event, payload)
    result = yield
    @events << [event, payload, result]
    result
  end
end
