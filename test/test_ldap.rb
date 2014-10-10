require 'common'

class TestLDAPInstrumentation < Test::Unit::TestCase
  def setup
    @connection = flexmock(:connection, :close => true)
    flexmock(Net::LDAP::Connection).should_receive(:new).and_return(@connection)

    @service = MockInstrumentationService.new
    @ldap = Net::LDAP.new \
      :server => "test.mocked.com", :port => 636,
      :force_no_page => true, # so server capabilities are not queried
      :instrumentation_service => @service
  end

  def test_instrument_bind
    events = @service.subscribe "bind.net_ldap"

    bind_result = flexmock(:bind_result, :success? => true)
    @connection.should_receive(:bind).with(Hash).and_return(bind_result)

    assert @ldap.bind

    payload, result = events.pop
    assert result
    assert_equal bind_result, payload[:bind]
  end

  def test_instrument_search
    events = @service.subscribe "search.net_ldap"

    @connection.should_receive(:bind).and_return(flexmock(:bind_result, :result_code => 0))
    @connection.should_receive(:search).with(Hash, Proc).
                yields(entry = Net::LDAP::Entry.new("uid=user1,ou=users,dc=example,dc=com")).
                and_return(flexmock(:search_result, :success? => true, :result_code => 0))

    refute_nil @ldap.search(:filter => "(uid=user1)")

    payload, result = events.pop
    assert_equal [entry], result
    assert_equal [entry], payload[:result]
    assert_equal "(uid=user1)", payload[:filter]
  end
end
