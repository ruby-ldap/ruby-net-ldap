# $Id$
#
#


$:.unshift "lib"

require 'net/snmp'
require 'stringio'


class TestSnmp < Test::Unit::TestCase

  SnmpRequest = "0'\002\001\000\004\006public\240\032\002\002?*\002\001\000\002\001\0000\0160\f\006\b+\006\001\002\001\001\001\000\005\000"

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

  def test_consume_string
      data = "xxx"
      assert_equal( nil, data.read_ber! )
      assert_equal( "xxx", data )

      data = SnmpRequest + "!!!"
      ary = data.read_ber!( Net::SNMP::AsnSyntax )
      assert_equal( "!!!", data )
      assert ary.is_a?(Array)
      assert ary.is_a?(Net::BER::BerIdentifiedArray)
  end

end


