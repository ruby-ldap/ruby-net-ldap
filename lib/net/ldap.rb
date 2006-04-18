# $Id$
#
# Net::LDAP for Ruby
#
#
#
# Copyright (C) 2006 by Francis Cianfrocca. All Rights Reserved.
#
# Gmail: garbagecat10
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
#
# == Miscellaneous
#
# For reasons relating to the source-code layout, this file doesn't
# require all the outboard stuff it actually needs, like netber.
# Until we figure out how to do that without damaging the directory
# structure, we're reliant on user programs to explicitly require
# everything, and in the correct order too!
#
# == BUGS:
#
# Try querying the objectGUID attribute from an A/D. It's a binary value
# which we're reading correctly, but we need to make sure it gets base64-encoded
# if we're going to put it out to an LDIF.
#



require 'socket'
require 'net/ber'
require 'net/ldap/pdu'
require 'net/ldap/filter'
require 'net/ldap/dataset'


module Net


  #
  # class LDAP
  #
  class LDAP

    class LdapError < Exception; end

    AsnSyntax = {
      :application => {
        :constructed => {
          0 => :array,              # BindRequest
          1 => :array,              # BindResponse
          2 => :array,              # UnbindRequest
          3 => :array,              # SearchRequest
          4 => :array,              # SearchData
          5 => :array,              # SearchResult
          6 => :array,              # ModifyRequest
          7 => :array,              # ModifyResponse
          8 => :array,              # AddRequest
          9 => :array,              # AddResponse
          10 => :array,             # DelRequest
          11 => :array,             # DelResponse
          12 => :array,             # ModifyRdnRequest
          13 => :array,             # ModifyRdnResponse
          14 => :array,             # CompareRequest
          15 => :array,             # CompareResponse
          16 => :array,             # AbandonRequest
        }
      },
      :context_specific => {
        :primitive => {
          0 => :string,             # password
          1 => :string,             # Kerberos v4
          2 => :string,             # Kerberos v5
        }
      }
    }

    DefaultHost = "127.0.0.1"
    DefaultPort = 389
    DefaultAuth = {:method => :anonymous}


    ResultStrings = {
      0 => "Success",
      1 => "Operations Error",
      16 => "No Such Attribute",
      17 => "Undefined Attribute Type",
      20 => "Attribute or Value Exists",
      32 => "No Such Object",
      34 => "Invalid DN Syntax",
      48 => "Invalid DN Syntax",
      48 => "Inappropriate Authentication",
      49 => "Invalid Credentials",
      50 => "Insufficient Access Rights",
      51 => "Busy",
      52 => "Unavailable",
      53 => "Unwilling to perform",
      68 => "Entry Already Exists"
    }

    #
    # LDAP::result2string
    #
    def LDAP::result2string code
      ResultStrings[code] || "unknown result (#{code})"
    end 

    #
    # initialize
    #
    def initialize args
      @host = args[:host] || DefaultHost
      @port = args[:port] || DefaultPort
      @verbose = false # Make this configurable with a switch on the class.
      @auth = args[:auth] || DefaultAuth

      # This variable is only set when we are created with LDAP::open.
      # All of our internal methods will connect using it, or else
      # they will create their own.
      @open_connection = nil
    end

    #
    # open
    #
    def LDAP::open args
      ldap = LDAP.new args
      ldap.open {|ldap1| yield ldap1 }
    end


    # This method opens a network connection to the server and then
    # passes self to the caller-supplied block. The connection is
    # closed when the block completes. It's for executing multiple
    # LDAP operations without requiring a separate network connection
    # (and authentication) for each one.
    #--
    # First we make a connection and then a binding, but we don't
    # do anything with the bind results.
    # We then pass self to the caller's block, where he will execute
    # his LDAP operations. Of course they will all generate auth failures
    # if the bind was unsuccessful.
    def open
      raise LdapError.new( "open already in progress" ) if @open_connection
      @open_connection = Connection.new( :host => @host, :port => @port )
      @open_connection.bind @auth
      yield self
      @open_connection.close
    end


    #
    # search
    #--
    # If an open call is in progress (@open_connection will be non-nil),
    # then ASSUME a bind has been performed and accepted, and just
    # execute the search.
    # If @open_connection is nil, then we have to connect, bind,
    # search, and then disconnect. (The disconnect is not strictly
    # necessary but it's friendlier to the network to do it here
    # rather than waiting for Ruby's GC.)
    # Note that in the standalone case, we're permitting the caller
    # to modify the auth parms.
    #
    def search args
      if @open_connection
        result_code = @open_connection.search( args ) {|values|
          block_given? and yield( values )
        }
        result_code
      else
        result_code = 0
        conn = Connection.new( :host => @host, :port => @port )
        if (result_code = conn.bind( args[:auth] || @auth )) == 0
          result_code = conn.search( args ) {|values|
            block_given? and yield( values )
          }
        end
        conn.close
        result_code
      end

    end

    #
    # bind
    # Bind and unbind.
    # Can serve as a connectivity test as well as an auth test.
    #--
    # If there is an @open_connection, then perform the bind
    # on it. Otherwise, connect, bind, and disconnect.
    # The latter operation is obviously useful only as an auth check.
    #
    def bind
      if @open_connection
        @open_connection.bind @auth
      else
        conn = Connection.new( :host => @host, :port => @port )
        result = conn.bind @auth
        conn.close
        result
      end
    end

    #
    # bind_as
    # This is for testing authentication credentials.
    # Most likely a "standard" name (like a CN or an email
    # address) will be presented along with a password.
    # We'll bind with the main credential given in the
    # constructor, query the full DN of the user given
    # to us as a parameter, then unbind and rebind as the
    # new user.
    #
    def bind_as
    end

    #
    # add
    # Add a full RDN to the remote DIS.
    #
    def add args
      if @open_connection
          @open_connection.add( args )
      else
        result_code = 0
        conn = Connection.new( :host => @host, :port => @port )
        if (result_code = conn.bind( args[:auth] || @auth )) == 0
          result_code = conn.add( args )
        end
        conn.close
        result_code
      end
    end


    #
    # modify
    # Modify the attributes of an entry on the remote DIS.
    #
    def modify args
      if @open_connection
          @open_connection.modify( args )
      else
        result_code = 0
        conn = Connection.new( :host => @host, :port => @port )
        if (result_code = conn.bind( args[:auth] || @auth )) == 0
          result_code = conn.modify( args )
        end
        conn.close
        result_code
      end
    end

    #
    # rename
    # Rename an entry on the remote DIS by changing the last RDN of its DN.
    #
    def rename args
      if @open_connection
          @open_connection.rename( args )
      else
        result_code = 0
        conn = Connection.new( :host => @host, :port => @port )
        if (result_code = conn.bind( args[:auth] || @auth )) == 0
          result_code = conn.rename( args )
        end
        conn.close
        result_code
      end
    end

  end # class LDAP



  class LDAP
  class Connection

    LdapVersion = 3


    #
    # initialize
    #
    def initialize server
      begin
        @conn = TCPsocket.new( server[:host], server[:port] )
      rescue
        raise LdapError.new( "no connection to server" )
      end

      block_given? and yield self
    end


    #
    # close
    # This is provided as a convenience method to make
    # sure a connection object gets closed without waiting
    # for a GC to happen. Clients shouldn't have to call it,
    # but perhaps it will come in handy someday.
    def close
      @conn.close
      @conn = nil
    end

    #
    # next_msgid
    #
    def next_msgid
      @msgid ||= 0
      @msgid += 1
    end


    #
    # bind
    #
    def bind auth
      user,psw = case auth[:method]
      when :anonymous
        ["",""]
      when :simple
        [auth[:username] || auth[:dn], auth[:password]]
      end
      raise LdapError.new( "invalid binding information" ) unless (user && psw)

      msgid = next_msgid.to_ber
      request = [LdapVersion.to_ber, user.to_ber, psw.to_ber_contextspecific(0)].to_ber_appsequence(0)
      request_pkt = [msgid, request].to_ber_sequence
      @conn.write request_pkt

      (be = @conn.read_ber(AsnSyntax) and pdu = Net::LdapPdu.new( be )) or raise LdapError.new( "no bind result" )
      pdu.result_code
    end

    #
    # search
    # TODO, certain search parameters are hardcoded.
    # TODO, if we mis-parse the server results or the results are wrong, we can block
    # forever. That's because we keep reading results until we get a type-5 packet,
    # which might never come. We need to support the time-limit in the protocol.
    #
    def search args
      search_filter = (args && args[:filter]) || Filter.eq( "objectclass", "*" )
      search_base = (args && args[:base]) || "dc=example,dc=com"
      search_attributes = ((args && args[:attributes]) || []).map {|attr| attr.to_s.to_ber}
      request = [
        search_base.to_ber,
        2.to_ber_enumerated,
        0.to_ber_enumerated,
        0.to_ber,
        0.to_ber,
        false.to_ber,
        search_filter.to_ber,
        search_attributes.to_ber_sequence
      ].to_ber_appsequence(3)
      pkt = [next_msgid.to_ber, request].to_ber_sequence
      @conn.write pkt

      search_results = {}
      result_code = 0

      while (be = @conn.read_ber(AsnSyntax)) && (pdu = LdapPdu.new( be ))
        case pdu.app_tag
        when 4 # search-data
          search_results [pdu.search_dn] = pdu.search_attributes
        when 5 # search-result
          result_code = pdu.result_code
          block_given? and yield( search_results )
          break
        else
          raise LdapError.new( "invalid response-type in search: #{pdu.app_tag}" )
        end
      end

      result_code
    end

    #
    # modify
    # TODO, need to support a time limit, in case the server fails to respond.
    # TODO!!! We're throwing an exception here on empty DN.
    # Should return a proper error instead, probaby from farther up the chain.
    # TODO!!! If the user specifies a bogus opcode, we'll throw a
    # confusing error here ("to_ber_enumerated is not defined on nil").
    #
    def modify args
      modify_dn = args[:dn] or raise "Unable to modify empty DN"
      modify_ops = []
      a = args[:operations] and a.each {|op, attr, values|
        # TODO, fix the following line, which gives a bogus error
        # if the opcode is invalid.
        op_1 = {:add => 0, :delete => 1, :replace => 2} [op.to_sym].to_ber_enumerated
        modify_ops << [op_1, [attr.to_s.to_ber, values.to_a.map {|v| v.to_ber}.to_ber_set].to_ber_sequence].to_ber_sequence
      }

      request = [modify_dn.to_ber, modify_ops.to_ber_sequence].to_ber_appsequence(6)
      pkt = [next_msgid.to_ber, request].to_ber_sequence
      @conn.write pkt

      (be = @conn.read_ber(AsnSyntax)) && (pdu = LdapPdu.new( be )) && (pdu.app_tag == 7) or raise LdapError.new( "response missing or invalid" )
      pdu.result_code
    end


    #
    # add
    # TODO, need to support a time limit, in case the server fails to respond.
    #
    def add args
      add_dn = args[:dn] or raise LdapError.new("Unable to add empty DN")
      add_attrs = []
      a = args[:attributes] and a.each {|k,v|
        add_attrs << [ k.to_s.to_ber, v.to_a.map {|m| m.to_ber}.to_ber_set ].to_ber_sequence
      }

      request = [add_dn.to_ber, add_attrs.to_ber_sequence].to_ber_appsequence(8)
      pkt = [next_msgid.to_ber, request].to_ber_sequence
      @conn.write pkt

      (be = @conn.read_ber(AsnSyntax)) && (pdu = LdapPdu.new( be )) && (pdu.app_tag == 9) or raise LdapError.new( "response missing or invalid" )
      pdu.result_code
    end


    #
    # rename
    # TODO, need to support a time limit, in case the server fails to respond.
    #
    def rename args
      old_dn = args[:olddn] or raise "Unable to rename empty DN"
      new_rdn = args[:newrdn] or raise "Unable to rename to empty RDN"
      delete_attrs = args[:delete_attributes] ? true : false

      request = [old_dn.to_ber, new_rdn.to_ber, delete_attrs.to_ber].to_ber_appsequence(12)
      pkt = [next_msgid.to_ber, request].to_ber_sequence
      @conn.write pkt

      (be = @conn.read_ber(AsnSyntax)) && (pdu = LdapPdu.new( be )) && (pdu.app_tag == 13) or raise LdapError.new( "response missing or invalid" )
      pdu.result_code
    end


  end # class Connection
  end # class LDAP


end # module Net


#------------------------------------------------------

if __FILE__ == $0
  puts "No default action"
end





