# $Id$
#
#


$:.unshift "lib"

require 'net/ldap'
require 'stringio'


class TestBer < Test::Unit::TestCase

  def setup
  end

  # TODO: Add some much bigger numbers
  # 5000000000 is a Bignum, which hits different code.
  def test_ber_integers
    assert_equal( "\002\001\005", 5.to_ber )
    assert_equal( "\002\002\001\364", 500.to_ber )
    assert_equal( "\002\003\0\303P", 50000.to_ber )
    assert_equal( "\002\005\001*\005\362\000", 5000000000.to_ber )
  end

  def test_ber_bignums
      # Some of these values are Fixnums and some are Bignums. Different BER code.
      [
	  5,
	  50,
	  500,
	  5000,
	  50000,
	  500000,
	  5000000,
	  50000000,
	  500000000,
	  1000000000,
	  2000000000,
	  3000000000,
	  4000000000,
	  5000000000
      ].each {|val|
	  assert_equal( val, val.to_ber.read_ber )
      }
  end

  def test_ber_parsing
    assert_equal( 6, "\002\001\006".read_ber( Net::LDAP::AsnSyntax ))
    assert_equal( "testing", "\004\007testing".read_ber( Net::LDAP::AsnSyntax ))
  end


  def test_ber_parser_on_ldap_bind_request
    s = StringIO.new "0$\002\001\001`\037\002\001\003\004\rAdministrator\200\vad_is_bogus"
    assert_equal( [1, [3, "Administrator", "ad_is_bogus"]], s.read_ber( Net::LDAP::AsnSyntax ))
  end


  def test_oid
      oid = Net::BER::BerIdentifiedOid.new( [1,3,6,1,2,1,1,1,0] )
      assert_equal( "\006\b+\006\001\002\001\001\001\000", oid.to_ber )
      oid = Net::BER::BerIdentifiedOid.new( "1.3.6.1.2.1.1.1.0" )
      assert_equal( "\006\b+\006\001\002\001\001\001\000", oid.to_ber )
  end


end


