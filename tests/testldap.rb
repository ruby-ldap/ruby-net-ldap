# $Id$
#
#


require 'lib/netber'
require 'lib/netldap'
require 'lib/ldappdu'
require 'lib/netldapfilter'
require 'stringio'


class TestLdapClient < Test::Unit::TestCase

  def setup
    @host = "127.0.0.1"
    @port = 3890
    @auth = {
      :method => :simple,
      :username => "cn=bigshot,dc=bayshorenetworks,dc=com",
      :password => "opensesame"
    }

  end

  # Binding tests.
  # Need tests for all kinds of network failures and incorrect auth.
  # TODO: Implement a class-level timeout for operations like bind.
  # Search has a timeout defined at the protocol level, other ops do not.
  # TODO, use constants for the LDAP result codes, rather than hardcoding them.
  def test_bind
    ldap = Net::LDAP.new :host => @host, :port => @port, :auth => @auth
    assert_equal( 0, ldap.bind )

    bad_username = @auth.merge( {:username => "cn=badguy,dc=imposters,dc=com"} )
    ldap = Net::LDAP.new :host => @host, :port => @port, :auth => bad_username
    assert_equal( 48, ldap.bind )

    bad_password = @auth.merge( {:password => "cornhusk"} )
    ldap = Net::LDAP.new :host => @host, :port => @port, :auth => bad_password
    assert_equal( 49, ldap.bind )
  end

  def test_search
    ldap = Net::LDAP.new :host => @host, :port => @port, :auth => @auth

    search = {:base => "dc=smalldomain,dc=com"}
    assert_equal( 32, ldap.search( search ))
    
    search = {:base => "dc=bigdomain,dc=com"}
    assert_equal( 0, ldap.search( search ))
    
    ldap.search( search ) {|res|
      p res
    }
    

  end


end


