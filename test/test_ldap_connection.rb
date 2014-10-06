require 'common'

class TestLDAP < Test::Unit::TestCase
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

  def test_write_request
    mock = Minitest::Mock.new
    mock.expect(:write, true, [[1, "request"].to_ber_sequence])
    conn = Net::LDAP::Connection.new(:socket => mock)
    conn.write_request("request")
  end

  def test_write_request_with_controls
    mock = Minitest::Mock.new
    mock.expect(:write, true, [[1, "request", "controls"].to_ber_sequence])
    conn = Net::LDAP::Connection.new(:socket => mock)
    conn.write_request("request", "controls")
  end

  def test_write_request_increments_msgid
    mock = Minitest::Mock.new
    mock.expect(:write, true, [[1, "request1"].to_ber_sequence])
    mock.expect(:write, true, [[2, "request2"].to_ber_sequence])
    conn = Net::LDAP::Connection.new(:socket => mock)
    conn.write_request("request1")
    conn.write_request("request2")
  end
end
