require_relative 'test_helper'

class TestLDAPConnection < Test::Unit::TestCase
  def test_unresponsive_host
    assert_raise Net::LDAP::LdapError do
      Net::LDAP::Connection.new(:host => 'test.mocked.com', :port => 636)
    end
  end

  def test_blocked_port
    flexmock(TCPSocket).should_receive(:new).and_raise(SocketError)
    assert_raise Net::LDAP::LdapError do
      Net::LDAP::Connection.new(:host => 'test.mocked.com', :port => 636)
    end
  end

  def test_raises_unknown_exceptions
    error = Class.new(StandardError)
    flexmock(TCPSocket).should_receive(:new).and_raise(error)
    assert_raise error do
      Net::LDAP::Connection.new(:host => 'test.mocked.com', :port => 636)
    end
  end

  def test_modify_ops_delete
    args = { :operations => [ [ :delete, "mail" ] ] }
    result = Net::LDAP::Connection.modify_ops(args[:operations])
    expected = [ "0\r\n\x01\x010\b\x04\x04mail1\x00" ]
    assert_equal(expected, result)
  end

  def test_modify_ops_add
    args = { :operations => [ [ :add, "mail", "testuser@example.com" ] ] }
    result = Net::LDAP::Connection.modify_ops(args[:operations])
    expected = [ "0#\n\x01\x000\x1E\x04\x04mail1\x16\x04\x14testuser@example.com" ]
    assert_equal(expected, result)
  end

  def test_modify_ops_replace
    args = { :operations =>[ [ :replace, "mail", "testuser@example.com" ] ] }
    result = Net::LDAP::Connection.modify_ops(args[:operations])
    expected = [ "0#\n\x01\x020\x1E\x04\x04mail1\x16\x04\x14testuser@example.com" ]
    assert_equal(expected, result)
  end

  def test_write
    mock = flexmock("socket")
    mock.should_receive(:write).with([1.to_ber, "request"].to_ber_sequence).and_return(true)
    conn = Net::LDAP::Connection.new(:socket => mock)
    conn.send(:write, "request")
  end

  def test_write_with_controls
    mock = flexmock("socket")
    mock.should_receive(:write).with([1.to_ber, "request", "controls"].to_ber_sequence).and_return(true)
    conn = Net::LDAP::Connection.new(:socket => mock)
    conn.send(:write, "request", "controls")
  end

  def test_write_increments_msgid
    mock = flexmock("socket")
    mock.should_receive(:write).with([1.to_ber, "request1"].to_ber_sequence).and_return(true)
    mock.should_receive(:write).with([2.to_ber, "request2"].to_ber_sequence).and_return(true)
    conn = Net::LDAP::Connection.new(:socket => mock)
    conn.send(:write, "request1")
    conn.send(:write, "request2")
  end
end


class TestLDAPConnectionErrors < Test::Unit::TestCase
  def setup
    @tcp_socket = flexmock(:connection)
    @tcp_socket.should_receive(:write)
    flexmock(TCPSocket).should_receive(:new).and_return(@tcp_socket)
    @connection = Net::LDAP::Connection.new(:host => 'test.mocked.com', :port => 636)
  end

  def test_error_failed_operation
    ber = Net::BER::BerIdentifiedArray.new([53, "", "The provided password value was rejected by a password validator:  The provided password did not contain enough characters from the character set 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.  The minimum number of characters from that set that must be present in user passwords is 1"])
    ber.ber_identifier = Net::LDAP::PDU::ModifyResponse
    @tcp_socket.should_receive(:read_ber).and_return([2, ber])

    result = @connection.modify(:dn => "1", :operations => [[:replace, "mail", "something@sothsdkf.com"]])
    assert result.failure?, "should be failure"
    assert_equal "The provided password value was rejected by a password validator:  The provided password did not contain enough characters from the character set 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.  The minimum number of characters from that set that must be present in user passwords is 1", result.error_message
  end

  def test_no_error_on_success
    ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
    ber.ber_identifier = Net::LDAP::PDU::ModifyResponse
    @tcp_socket.should_receive(:read_ber).and_return([2, ber])

    result = @connection.modify(:dn => "1", :operations => [[:replace, "mail", "something@sothsdkf.com"]])
    assert result.success?, "should be success"
    assert_equal "", result.error_message
  end
end

class TestLDAPConnectionInstrumentation < Test::Unit::TestCase
  def setup
    @tcp_socket = flexmock(:connection)
    @tcp_socket.should_receive(:write)
    flexmock(TCPSocket).should_receive(:new).and_return(@tcp_socket)

    @service = MockInstrumentationService.new
    @connection = Net::LDAP::Connection.new \
      :host => 'test.mocked.com',
      :port => 636,
      :instrumentation_service => @service
  end

  def test_write_net_ldap_connection_event
    ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
    ber.ber_identifier = Net::LDAP::PDU::BindResult
    read_result = [2, ber]
    @tcp_socket.should_receive(:read_ber).and_return(read_result)

    events = @service.subscribe "write.net_ldap_connection"

    result = @connection.bind(method: :anon)
    assert result.success?, "should be success"

    # a write event
    payload, result = events.pop
    assert payload.has_key?(:result)
    assert payload.has_key?(:content_length)
  end

  def test_read_net_ldap_connection_event
    ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
    ber.ber_identifier = Net::LDAP::PDU::BindResult
    read_result = [2, ber]
    @tcp_socket.should_receive(:read_ber).and_return(read_result)

    events = @service.subscribe "read.net_ldap_connection"

    result = @connection.bind(method: :anon)
    assert result.success?, "should be success"

    # a read event
    payload, result = events.pop
    assert payload.has_key?(:result)
    assert_equal read_result, result
  end

  def test_bind_net_ldap_connection_event
    ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
    ber.ber_identifier = Net::LDAP::PDU::BindResult
    bind_result = [2, ber]
    @tcp_socket.should_receive(:read_ber).and_return(bind_result)

    events = @service.subscribe "bind.net_ldap_connection"

    result = @connection.bind(method: :anon)
    assert result.success?, "should be success"

    # a read event
    payload, result = events.pop
    assert payload.has_key?(:result)
    assert result.success?, "should be success"
  end

  def test_search_net_ldap_connection_event
    # search data
    search_data_ber = Net::BER::BerIdentifiedArray.new([2, [
      "uid=user1,ou=OrgUnit2,ou=OrgUnitTop,dc=openldap,dc=ghe,dc=local",
      [ ["uid", ["user1"]] ]
    ]])
    search_data_ber.ber_identifier = Net::LDAP::PDU::SearchReturnedData
    search_data = [2, search_data_ber]
    # search result (end of results)
    search_result_ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
    search_result_ber.ber_identifier = Net::LDAP::PDU::SearchResult
    search_result = [2, search_result_ber]
    @tcp_socket.should_receive(:read_ber).and_return(search_data).
                                          and_return(search_result)

    events = @service.subscribe "search.net_ldap_connection"

    result = @connection.search(filter: "(uid=user1)")
    assert result.success?, "should be success"

    # a search event
    payload, result = events.pop
    assert payload.has_key?(:result)
    assert payload.has_key?(:filter)
    assert_equal "(uid=user1)", payload[:filter].to_s
    assert result
  end
end
