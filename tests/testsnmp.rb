# $Id$
#
#


$:.unshift "lib"

require 'net/snmp'
require 'stringio'


class TestSnmp < Test::Unit::TestCase

  SnmpGetRequest = "0'\002\001\000\004\006public\240\032\002\002?*\002\001\000\002\001\0000\0160\f\006\b+\006\001\002\001\001\001\000\005\000"

  def setup
  end

  def teardown
  end

  def test_invalid_packet
      data = "xxxx"
      assert_raise( Net::BER::BerError ) {
	ary = data.read_ber(Net::SNMP::AsnSyntax)
      }

  end

  # The method String#read_ber! added by Net::BER consumes a well-formed BER object
  # from the head of a string. If it doesn't find a complete, well-formed BER object,
  # it returns nil and leaves the string unchanged. If it finds an object, it returns
  # the object and removes it from the head of the string. This is good for handling
  # partially-received data streams, such as from network connections.
  def test_consume_string
      data = "xxx"
      assert_equal( nil, data.read_ber! )
      assert_equal( "xxx", data )

      data = SnmpGetRequest + "!!!"
      ary = data.read_ber!( Net::SNMP::AsnSyntax )
      assert_equal( "!!!", data )
      assert ary.is_a?(Array)
      assert ary.is_a?(Net::BER::BerIdentifiedArray)
  end

  def test_weird_packet
      assert_raise( Net::SnmpPdu::Error ) {
	Net::SnmpPdu.new("aaaaaaaaaaaaaa")
      }
  end

  def test_packet
      data = SnmpGetRequest.dup
      pkt = data.read_ber(Net::SNMP::AsnSyntax)
      assert pkt.is_a?(Net::BER::BerIdentifiedArray)
      assert_equal( 48, pkt.ber_identifier) # Constructed [0], signifies GetRequest

      pdu = Net::SnmpPdu.new(pkt)
      assert_equal(:get_request, pdu.pdu_type )
      assert_equal(16170, pdu.request_id ) # whatever was in the test data. 16170 is not magic.
      assert_equal( [[1,3,6,1,2,1,1,1,0]], pdu.variables )
  end
end


