# $Id$
#
# Net::LDAP for Ruby
#
#
# Copyright (C) 2006 by Francis Cianfrocca. All Rights Reserved.
#
# Written and maintained by Francis Cianfrocca, gmail: garbagecat10.
#
# This program is free software.
# You may re-distribute and/or modify this program under the same terms
# as Ruby itself: Ruby Distribution License or GNU General Public License.
#
#
# See Net::LDAP for documentation and usage samples.
#


require 'socket'
require 'ostruct'
require 'net/ber'
require 'net/ldap/pdu'
require 'net/ldap/filter'
require 'net/ldap/dataset'
require 'net/ldap/psw'


module Net


  # == Net::LDAP
  #
  # This library provides a pure-Ruby implementation of the
  # LDAP client protocol, per RFC-1777.
  # It can be used to access any server which implements the
  # LDAP protocol.
  #
  # Net::LDAP is intended to provide full LDAP functionality
  # while hiding the more arcane aspects
  # the LDAP protocol itself, and thus presenting as Ruby-like
  # a programming interface as possible.
  # 
  # === Quick-start for the Impatient
  #  require 'rubygems'
  #  require 'net/ldap'
  #  
  #  ldap = Net::LDAP.new :host => server_ip_address,
  #       :port => 389,
  #       :auth => {
  #             :method => :simple,
  #             :username => "cn=manager,dc=example,dc=com",
  #             :password => "opensesame"
  #       }
  #
  #  filter = Net::LDAP::Filter.eq?( "cn", "George*" )
  #  treebase = "dc=example,dc=com"
  #  
  #  ldap.search( :base => treebase, :filter => filter ) do |result|
  #    result.each do |dn, attrs|
  #      puts "DN: #{dn}"
  #      attrs.each do |attr, values|
  #        puts "***Attr: #{attr}"
  #        values.each do |value|
  #          puts "      #{value}"
  #        end
  #      end
  #    end
  #  end
  #  
  #  p ldap.get_operation_result
  #  
  #
  # == Quick introduction to LDAP
  #
  # We're going to provide a quick and highly informal introduction to LDAP
  # terminology and
  # typical operations. If you're comfortable with this material, skip
  # ahead to "How to use Net::LDAP." If you want a more rigorous treatment
  # of this material, we recommend you start with the various IETF and ITU
  # standards that control LDAP.
  #
  # === Entities
  # LDAP is an Internet-standard protocol used to access directory servers.
  # The basic search unit is the <i>entity,</i> which corresponds to
  # a person or other domain-specific object.
  # A directory service which supports the LDAP protocol typically
  # stores information about a number of entities.
  #
  # === Principals
  # LDAP servers are typically used to access information about people,
  # but also very often about such items as printers, computers, and other
  # resources. To reflect this, LDAP uses the term <i>entity,</i> or less
  # commonly, <i>principal,</i> to denote its basic data-storage unit.
  # 
  #
  # === Distinguished Names
  # In LDAP's view of the world,
  # an entity is uniquely identified by a globally-unique text string
  # called a <i>Distinguished Name,</i> originally defined in the X.400
  # standards from which LDAP is ultimately derived.
  # Much like a DNS hostname, a DN is a "flattened" text representation
  # of a string of tree nodes. Also like DNS (and unlike Java package
  # names), a DN expresses a chain of tree-nodes written from left to right
  # in order from the most-resolved node to the most-general one.
  #
  # If you know the DN of a person or other entity, then you can query
  # an LDAP-enabled directory for information (attributes) about the entity.
  # Alternatively, you can query the directory for a list of DNs matching
  # a set of criteria that you supply.
  #
  # === Attributes
  #
  # In the LDAP view of the world, a DN uniquely identifies an entity.
  # Information about the entity is stored as a set of <i>Attributes.</i>
  # An attribute is a text string which is associated with zero or more
  # values. Most LDAP-enabled directories store a well-standardized
  # range of attributes, and constrain their values according to standard
  # rules.
  #
  # A good example of an attribute is <tt>cn,</tt> which stands for "Common Name."
  # In many directories, this attribute is used to store a string consisting of
  # a person's first and last names. Most directories enforce the convention that
  # an entity's <tt>cn</tt> attribute have <i>exactly one</i> value. In LDAP
  # jargon, that means that <tt>cn</tt> must be <i>present</i> and
  # <i>single-valued.</i>
  #
  # Another attribute is <tt>mail,</tt> which is used to store email addresses.
  # (No, there is no attribute called "email," perhaps because X.400 terminology
  # predates the invention of the term <i>email.</i>) <tt>mail</tt> differs
  # from <tt>cn</tt> in that most directories permit any number of values for the
  # <tt>mail</tt> attribute, including zero.
  #
  #
  # === Tree-Base
  # We said above that X.400 Distinguished Names are <i>globally unique.</i>
  # In a manner reminiscent of DNS, LDAP supposes that each directory server
  # contains authoritative attribute data for a set of DNs corresponding
  # to a specific sub-tree of the (notional) global directory tree.
  # This subtree is generally configured into a directory server when it is
  # created. It matters for this discussion because most servers will not
  # allow you to query them unless you specify a correct tree-base.
  #
  # Let's say you work for the engineering department of Big Company, Inc.,
  # whose internet domain is bigcompany.com. You may find that your departmental
  # directory is stored in a server with a defined tree-base of
  #  ou=engineering,dc=bigcompany,dc=com
  # You will need to supply this string as the <i>tree-base</i> when querying this
  # directory. (Ou is a very old X.400 term meaning "organizational unit."
  # Dc is a more recent term meaning "domain component.")
  #
  # === LDAP Versions
  # (stub, discuss v2 and v3)
  #
  # === LDAP Operations
  # The essential operations are: <i>bind, search, add, modify, delete, and rename.</i>
  # ==== Bind
  # Bind supplies a user's authentication credentials to a server, which in turn verifies
  # or rejects them. There is a range of possibilities for credentials, but most directories
  # support a simple username and password authentication.
  #
  # Taken by itself, the bind operation can be used to authenticate a user against information
  # stored in a directory, for example to permit or deny access to some other resource.
  # In terms of the other LDAP operations, most directories require a successful bind to
  # be performed before the other operations will be permitted. Some servers permit certain
  # operations to be performed with an "anonymous" binding, meaning that no credentials are
  # presented by the user. (We're glossing over a lot of platform-specific detail here.)
  #
  # ==== Search
  # Searching the directory involves specifying a treebase, a set of <i>search filters,</i>
  # and a list of attribute values.
  # The filters specify ranges of possible values for particular attributes. Multiple
  # filters can be joined together with AND, OR, and NOT operators.
  # A server will respond to a search by returning a list of matching DNs together with a
  # set of attribute values for each entity, depending on what attributes the search requested.
  # 
  # ==== Add
  # An add operation specifies a new DN and an initial set of attribute values. If the operation
  # succeeds, a new entity with the corresponding DN and attributes is added to the directory.
  #
  # ==== Modify
  # Modify specifies an entity DN, and a list of attribute operations. Modify is used to change
  # the attribute values stored in the directory for a particular entity.
  # Modify may add or delete attributes (which are lists of values) or it change attributes by
  # adding to or deleting from their values.
  #
  # ==== Delete
  # The delete operation specifies an entity DN. If it succeeds, the entity and all its attributes
  # is removed from the directory.
  #
  # ==== Rename (or Modify RDN)
  # Rename (or Modify RDN) is an operation added to version 3 of the LDAP protocol. It responds to
  # the often-arising need to change the DN of an entity without discarding its attribute values.
  # In earlier LDAP versions, the only way to do this was to delete the whole entity and add it
  # again with a different DN.
  #
  # Rename works by taking an "old" DN (the one to change) and a "new RDN," which is the left-most
  # part of the DN string. If successful, rename changes the entity DN so that its left-most
  # node corresponds to the new RDN given in the request. (RDN, or "relative distinguished name,"
  # denotes a single tree-node as expressed in a DN, which is a chain of tree nodes.)
  #
  # == How to use Net::LDAP
  #
  # This is how to access Net::LDAP functionality in your Ruby programs
  # (note that at present, Net::LDAP is provided as a gem):
  #
  #  require 'rubygems'
  #  require 'net/ldap'
  #
  # Most operations with Net::LDAP start by instantiating a Net::LDAP object.
  # The constructor for this object takes arguments specifying the network location
  # (address and port) of the LDAP server, and also the binding (authentication)
  # credentials, typically a username and password.
  # Given an object of class Net:LDAP, you can then perform LDAP operations by calling
  # instance methods on the object. These are documented with usage examples below.
  #
  # The Net::LDAP library is designed to be very disciplined about how it makes network
  # connections to servers. This is different from many of the standard native-code
  # libraries that are provided on most platforms, and that share bloodlines with the
  # original Netscape/Michigan LDAP client implementations. These libraries sought to
  # insulate user code from the workings of the network. This is a good idea of course,
  # but the practical effect has been confusing and many difficult bugs have been caused
  # by the opacity of the native libraries, and their variable behavior across platforms.
  #
  # In general, Net::LDAP instance methods which invoke server operations make a connection
  # to the server when the method is called. They execute the operation (typically binding first)
  # and then disconnect from the server. The exception is Net::LDAP#open, which makes a connection
  # to the server and then keeps it open while it executes a user-supplied block. Net::LDAP#open
  # closes the connection on completion of the block.
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
      65 => "Object Class Violation",
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

    # This method will return a meaningful result any time after
    # a protocol operation (bind, search, add, modify, rename, delete)
    # has completed.
    # It returns an OpenStruct containing an LDAP result code (0 means success),
    # and a human-readable string.
    #  unless ldap.bind
    #    puts "Result: #{ldap.get_operation_result.code}"
    #    puts "Message: #{ldap.get_operation_result.message}"
    #  end
    #
    def get_operation_result
      os = OpenStruct.new
      if @result
        os.code = @result
      else
        os.code = 0
      end
      os.message = LDAP.result2string( os.code )
      os
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
        @result = @open_connection.search( args ) {|values|
          block_given? and yield( values )
        }
      else
        @result = 0
        conn = Connection.new( :host => @host, :port => @port )
        if (@result = conn.bind( args[:auth] || @auth )) == 0
          @result = conn.search( args ) {|values|
            block_given? and yield( values )
          }
        end
        conn.close
      end

      @result == 0
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
        @result = @open_connection.bind @auth
      else
        conn = Connection.new( :host => @host, :port => @port )
        @result = conn.bind @auth
        conn.close
      end

      @result == 0
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
          @result = @open_connection.add( args )
      else
        @result = 0
        conn = Connection.new( :host => @host, :port => @port )
        if (@result = conn.bind( args[:auth] || @auth )) == 0
          @result = conn.add( args )
        end
        conn.close
      end
      @result == 0
    end


    #
    # modify
    # Modify the attributes of an entry on the remote DIS.
    #
    def modify args
      if @open_connection
          @result = @open_connection.modify( args )
      else
        @result = 0
        conn = Connection.new( :host => @host, :port => @port )
        if (@result = conn.bind( args[:auth] || @auth )) == 0
          @result = conn.modify( args )
        end
        conn.close
      end
      @result == 0
    end

    #
    # rename
    # Rename an entry on the remote DIS by changing the last RDN of its DN.
    #
    def rename args
      if @open_connection
          @result = @open_connection.rename( args )
      else
        @result = 0
        conn = Connection.new( :host => @host, :port => @port )
        if (@result = conn.bind( args[:auth] || @auth )) == 0
          @result = conn.rename( args )
        end
        conn.close
      end
      @result == 0
    end

    # modify_rdn is an alias for rename.
    def modify_rdn args
      rename args
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





