# This is a private class used internally by the library. It should not
# be called by user code.
class Net::LDAP::Connection #:nodoc:
  include Net::LDAP::Instrumentation

  LdapVersion = 3
  MaxSaslChallenges = 10

  def initialize(server)
    @instrumentation_service = server[:instrumentation_service]

    begin
      @conn = server[:socket] || TCPSocket.new(server[:host], server[:port])
    rescue SocketError
      raise Net::LDAP::LdapError, "No such address or other socket error."
    rescue Errno::ECONNREFUSED
      raise Net::LDAP::LdapError, "Server #{server[:host]} refused connection on port #{server[:port]}."
    end

    if server[:encryption]
      setup_encryption server[:encryption]
    end

    yield self if block_given?
  end

  module GetbyteForSSLSocket
    def getbyte
      getc.ord
    end
  end

  module FixSSLSocketSyncClose
    def close
      super
      io.close
    end
  end

  def self.wrap_with_ssl(io)
    raise Net::LDAP::LdapError, "OpenSSL is unavailable" unless Net::LDAP::HasOpenSSL
    ctx = OpenSSL::SSL::SSLContext.new
    conn = OpenSSL::SSL::SSLSocket.new(io, ctx)
    conn.connect

    # Doesn't work:
    # conn.sync_close = true

    conn.extend(GetbyteForSSLSocket) unless conn.respond_to?(:getbyte)
    conn.extend(FixSSLSocketSyncClose)

    conn
  end

  #--
  # Helper method called only from new, and only after we have a
  # successfully-opened @conn instance variable, which is a TCP connection.
  # Depending on the received arguments, we establish SSL, potentially
  # replacing the value of @conn accordingly. Don't generate any errors here
  # if no encryption is requested. DO raise Net::LDAP::LdapError objects if encryption
  # is requested and we have trouble setting it up. That includes if OpenSSL
  # is not set up on the machine. (Question: how does the Ruby OpenSSL
  # wrapper react in that case?) DO NOT filter exceptions raised by the
  # OpenSSL library. Let them pass back to the user. That should make it
  # easier for us to debug the problem reports. Presumably (hopefully?) that
  # will also produce recognizable errors if someone tries to use this on a
  # machine without OpenSSL.
  #
  # The simple_tls method is intended as the simplest, stupidest, easiest
  # solution for people who want nothing more than encrypted comms with the
  # LDAP server. It doesn't do any server-cert validation and requires
  # nothing in the way of key files and root-cert files, etc etc. OBSERVE:
  # WE REPLACE the value of @conn, which is presumed to be a connected
  # TCPSocket object.
  #
  # The start_tls method is supported by many servers over the standard LDAP
  # port. It does not require an alternative port for encrypted
  # communications, as with simple_tls. Thanks for Kouhei Sutou for
  # generously contributing the :start_tls path.
  #++
  def setup_encryption(args)
    case args[:method]
    when :simple_tls
      @conn = self.class.wrap_with_ssl(@conn)
      # additional branches requiring server validation and peer certs, etc.
      # go here.
    when :start_tls
      msgid = next_msgid.to_ber
      request = [Net::LDAP::StartTlsOid.to_ber_contextspecific(0)].to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)
      request_pkt = [msgid, request].to_ber_sequence
      write request_pkt
      be = read
      raise Net::LDAP::LdapError, "no start_tls result" if be.nil?
      pdu = Net::LDAP::PDU.new(be)
      raise Net::LDAP::LdapError, "no start_tls result" if pdu.nil?
      if pdu.result_code.zero?
        @conn = self.class.wrap_with_ssl(@conn)
      else
        raise Net::LDAP::LdapError, "start_tls failed: #{pdu.result_code}"
      end
    else
      raise Net::LDAP::LdapError, "unsupported encryption method #{args[:method]}"
    end
  end

  #--
  # This is provided as a convenience method to make sure a connection
  # object gets closed without waiting for a GC to happen. Clients shouldn't
  # have to call it, but perhaps it will come in handy someday.
  #++
  def close
    @conn.close
    @conn = nil
  end

  # Internal: Reads and parses data from the configured connection.
  #
  # - syntax: the BER syntax to use to parse the read data with
  #
  # Returns basic BER objects.
  def read(syntax = Net::LDAP::AsnSyntax)
    instrument "read.net_ldap_connection", :syntax => syntax do |payload|
      @conn.read_ber(syntax) do |id, content_length|
        payload[:object_type_id] = id
        payload[:content_length] = content_length
      end
    end
  end
  private :read

  # Internal: Writes the given packet to the configured connection.
  #
  # - packet: the BER data packet to write on the socket.
  #
  # Returns the return value from writing to the connection, which in some
  # cases is the Integer number of bytes written to the socket.
  def write(packet)
    instrument "write.net_ldap_connection" do |payload|
      payload[:content_length] = @conn.write(packet)
    end
  end
  private :write

  def next_msgid
    @msgid ||= 0
    @msgid += 1
  end

  def bind(auth)
    instrument "bind.net_ldap_connection" do |payload|
      payload[:method] = meth = auth[:method]
      if [:simple, :anonymous, :anon].include?(meth)
        bind_simple auth
      elsif meth == :sasl
        bind_sasl(auth)
      elsif meth == :gss_spnego
        bind_gss_spnego(auth)
      else
        raise Net::LDAP::LdapError, "Unsupported auth method (#{meth})"
      end
    end
  end

  #--
  # Implements a simple user/psw authentication. Accessed by calling #bind
  # with a method of :simple or :anonymous.
  #++
  def bind_simple(auth)
    user, psw = if auth[:method] == :simple
                  [auth[:username] || auth[:dn], auth[:password]]
                else
                  ["", ""]
                end

    raise Net::LDAP::LdapError, "Invalid binding information" unless (user && psw)

    msgid = next_msgid.to_ber
    request = [LdapVersion.to_ber, user.to_ber,
      psw.to_ber_contextspecific(0)].to_ber_appsequence(0)
    request_pkt = [msgid, request].to_ber_sequence
    write request_pkt

    (be = read and pdu = Net::LDAP::PDU.new(be)) or raise Net::LDAP::LdapError, "no bind result"

    pdu
  end

  #--
  # Required parameters: :mechanism, :initial_credential and
  # :challenge_response
  #
  # Mechanism is a string value that will be passed in the SASL-packet's
  # "mechanism" field.
  #
  # Initial credential is most likely a string. It's passed in the initial
  # BindRequest that goes to the server. In some protocols, it may be empty.
  #
  # Challenge-response is a Ruby proc that takes a single parameter and
  # returns an object that will typically be a string. The
  # challenge-response block is called when the server returns a
  # BindResponse with a result code of 14 (saslBindInProgress). The
  # challenge-response block receives a parameter containing the data
  # returned by the server in the saslServerCreds field of the LDAP
  # BindResponse packet. The challenge-response block may be called multiple
  # times during the course of a SASL authentication, and each time it must
  # return a value that will be passed back to the server as the credential
  # data in the next BindRequest packet.
  #++
  def bind_sasl(auth)
    mech, cred, chall = auth[:mechanism], auth[:initial_credential],
      auth[:challenge_response]
    raise Net::LDAP::LdapError, "Invalid binding information" unless (mech && cred && chall)

    n = 0
    loop {
      msgid = next_msgid.to_ber
      sasl = [mech.to_ber, cred.to_ber].to_ber_contextspecific(3)
      request = [LdapVersion.to_ber, "".to_ber, sasl].to_ber_appsequence(0)
      request_pkt = [msgid, request].to_ber_sequence
      write request_pkt

      (be = read and pdu = Net::LDAP::PDU.new(be)) or raise Net::LDAP::LdapError, "no bind result"
      return pdu unless pdu.result_code == 14 # saslBindInProgress
      raise Net::LDAP::LdapError, "sasl-challenge overflow" if ((n += 1) > MaxSaslChallenges)

      cred = chall.call(pdu.result_server_sasl_creds)
    }

    raise Net::LDAP::LdapError, "why are we here?"
  end
  private :bind_sasl

  #--
  # PROVISIONAL, only for testing SASL implementations. DON'T USE THIS YET.
  # Uses Kohei Kajimoto's Ruby/NTLM. We have to find a clean way to
  # integrate it without introducing an external dependency.
  #
  # This authentication method is accessed by calling #bind with a :method
  # parameter of :gss_spnego. It requires :username and :password
  # attributes, just like the :simple authentication method. It performs a
  # GSS-SPNEGO authentication with the server, which is presumed to be a
  # Microsoft Active Directory.
  #++
  def bind_gss_spnego(auth)
    require 'ntlm'

    user, psw = [auth[:username] || auth[:dn], auth[:password]]
    raise Net::LDAP::LdapError, "Invalid binding information" unless (user && psw)

    nego = proc { |challenge|
      t2_msg = NTLM::Message.parse(challenge)
      t3_msg = t2_msg.response({ :user => user, :password => psw },
                               { :ntlmv2 => true })
      t3_msg.serialize
    }

    bind_sasl(:method => :sasl, :mechanism => "GSS-SPNEGO",
              :initial_credential => NTLM::Message::Type1.new.serialize,
              :challenge_response => nego)
  end
  private :bind_gss_spnego


  #--
  # Allow the caller to specify a sort control
  #
  # The format of the sort control needs to be:
  #
  # :sort_control => ["cn"]  # just a string
  # or
  # :sort_control => [["cn", "matchingRule", true]] #attribute, matchingRule, direction (true / false)
  # or
  # :sort_control => ["givenname","sn"] #multiple strings or arrays
  #
  def encode_sort_controls(sort_definitions)
    return sort_definitions unless sort_definitions

    sort_control_values = sort_definitions.map do |control|
      control = Array(control) # if there is only an attribute name as a string then infer the orderinrule and reverseorder
      control[0] = String(control[0]).to_ber,
      control[1] = String(control[1]).to_ber,
      control[2] = (control[2] == true).to_ber
      control.to_ber_sequence
    end
    sort_control = [
      Net::LDAP::LDAPControls::SORT_REQUEST.to_ber,
      false.to_ber,
      sort_control_values.to_ber_sequence.to_s.to_ber
    ].to_ber_sequence
  end

  #--
  # Alternate implementation, this yields each search entry to the caller as
  # it are received.
  #
  # TODO: certain search parameters are hardcoded.
  # TODO: if we mis-parse the server results or the results are wrong, we
  # can block forever. That's because we keep reading results until we get a
  # type-5 packet, which might never come. We need to support the time-limit
  # in the protocol.
  #++
  def search(args = {})
    search_filter = (args && args[:filter]) ||
      Net::LDAP::Filter.eq("objectclass", "*")
    search_filter = Net::LDAP::Filter.construct(search_filter) if search_filter.is_a?(String)
    search_base = (args && args[:base]) || "dc=example, dc=com"
    search_attributes = ((args && args[:attributes]) || []).map { |attr| attr.to_s.to_ber}
    return_referrals = args && args[:return_referrals] == true
    sizelimit = (args && args[:size].to_i) || 0
    raise Net::LDAP::LdapError, "invalid search-size" unless sizelimit >= 0
    paged_searches_supported = (args && args[:paged_searches_supported])

    attributes_only = (args and args[:attributes_only] == true)
    scope = args[:scope] || Net::LDAP::SearchScope_WholeSubtree
    raise Net::LDAP::LdapError, "invalid search scope" unless Net::LDAP::SearchScopes.include?(scope)

    sort_control = encode_sort_controls(args.fetch(:sort_controls){ false })

  deref = args[:deref] || Net::LDAP::DerefAliases_Never
  raise Net::LDAP::LdapError.new( "invalid alias dereferencing value" ) unless Net::LDAP::DerefAliasesArray.include?(deref)


    # An interesting value for the size limit would be close to A/D's
    # built-in page limit of 1000 records, but openLDAP newer than version
    # 2.2.0 chokes on anything bigger than 126. You get a silent error that
    # is easily visible by running slapd in debug mode. Go figure.
    #
    # Changed this around 06Sep06 to support a caller-specified search-size
    # limit. Because we ALWAYS do paged searches, we have to work around the
    # problem that it's not legal to specify a "normal" sizelimit (in the
    # body of the search request) that is larger than the page size we're
    # requesting. Unfortunately, I have the feeling that this will break
    # with LDAP servers that don't support paged searches!!!
    #
    # (Because we pass zero as the sizelimit on search rounds when the
    # remaining limit is larger than our max page size of 126. In these
    # cases, I think the caller's search limit will be ignored!)
    #
    # CONFIRMED: This code doesn't work on LDAPs that don't support paged
    # searches when the size limit is larger than 126. We're going to have
    # to do a root-DSE record search and not do a paged search if the LDAP
    # doesn't support it. Yuck.
    rfc2696_cookie = [126, ""]
    result_pdu = nil
    n_results = 0

    instrument "search.net_ldap_connection",
               :filter     => search_filter,
               :base       => search_base,
               :scope      => scope,
               :limit      => sizelimit,
               :sort       => sort_control,
               :referrals  => return_referrals,
               :deref      => deref,
               :attributes => search_attributes do |payload|
      loop do
        # should collect this into a private helper to clarify the structure
        query_limit = 0
        if sizelimit > 0
          if paged_searches_supported
            query_limit = (((sizelimit - n_results) < 126) ? (sizelimit -
                                                              n_results) : 0)
          else
            query_limit = sizelimit
          end
        end

        request = [
          search_base.to_ber,
          scope.to_ber_enumerated,
          deref.to_ber_enumerated,
          query_limit.to_ber, # size limit
          0.to_ber,
          attributes_only.to_ber,
          search_filter.to_ber,
          search_attributes.to_ber_sequence
        ].to_ber_appsequence(3)

        # rfc2696_cookie sometimes contains binary data from Microsoft Active Directory
        # this breaks when calling to_ber. (Can't force binary data to UTF-8)
        # we have to disable paging (even though server supports it) to get around this...

        controls = []
        controls <<
          [
            Net::LDAP::LDAPControls::PAGED_RESULTS.to_ber,
            # Criticality MUST be false to interoperate with normal LDAPs.
            false.to_ber,
            rfc2696_cookie.map{ |v| v.to_ber}.to_ber_sequence.to_s.to_ber
          ].to_ber_sequence if paged_searches_supported
        controls << sort_control if sort_control
        controls = controls.empty? ? nil : controls.to_ber_contextspecific(0)

        pkt = [next_msgid.to_ber, request, controls].compact.to_ber_sequence
        write pkt

        result_pdu = nil
        controls = []

        while (be = read) && (pdu = Net::LDAP::PDU.new(be))
          case pdu.app_tag
          when Net::LDAP::PDU::SearchReturnedData
            n_results += 1
            yield pdu.search_entry if block_given?
          when Net::LDAP::PDU::SearchResultReferral
            if return_referrals
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
          when Net::LDAP::PDU::SearchResult
            result_pdu = pdu
            controls = pdu.result_controls
            if return_referrals && pdu.result_code == 10
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
            break
          else
            raise Net::LDAP::LdapError, "invalid response-type in search: #{pdu.app_tag}"
          end
        end

        # count number of pages of results
        payload[:page_count] ||= 0
        payload[:page_count]  += 1

        # When we get here, we have seen a type-5 response. If there is no
        # error AND there is an RFC-2696 cookie, then query again for the next
        # page of results. If not, we're done. Don't screw this up or we'll
        # break every search we do.
        #
        # Noticed 02Sep06, look at the read_ber call in this loop, shouldn't
        # that have a parameter of AsnSyntax? Does this just accidentally
        # work? According to RFC-2696, the value expected in this position is
        # of type OCTET STRING, covered in the default syntax supported by
        # read_ber, so I guess we're ok.
        more_pages = false
        if result_pdu.result_code == 0 and controls
          controls.each do |c|
            if c.oid == Net::LDAP::LDAPControls::PAGED_RESULTS
              # just in case some bogus server sends us more than 1 of these.
              more_pages = false
              if c.value and c.value.length > 0
                cookie = c.value.read_ber[1]
                if cookie and cookie.length > 0
                  rfc2696_cookie[1] = cookie
                  more_pages = true
                end
              end
            end
          end
        end

        break unless more_pages
      end # loop

      # track total result count
      payload[:result_count] = n_results

      result_pdu || OpenStruct.new(:status => :failure, :result_code => 1, :message => "Invalid search")
    end # instrument
  end

  MODIFY_OPERATIONS = { #:nodoc:
    :add => 0,
    :delete => 1,
    :replace => 2
  }

  def self.modify_ops(operations)
    ops = []
    if operations
      operations.each { |op, attrib, values|
        # TODO, fix the following line, which gives a bogus error if the
        # opcode is invalid.
        op_ber = MODIFY_OPERATIONS[op.to_sym].to_ber_enumerated
        values = [ values ].flatten.map { |v| v.to_ber if v }.to_ber_set
        values = [ attrib.to_s.to_ber, values ].to_ber_sequence
        ops << [ op_ber, values ].to_ber
      }
    end
    ops
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  # TODO: We're throwing an exception here on empty DN. Should return a
  # proper error instead, probaby from farther up the chain.
  # TODO: If the user specifies a bogus opcode, we'll throw a confusing
  # error here ("to_ber_enumerated is not defined on nil").
  #++
  def modify(args)
    modify_dn = args[:dn] or raise "Unable to modify empty DN"
    ops = self.class.modify_ops args[:operations]
    request = [ modify_dn.to_ber,
      ops.to_ber_sequence ].to_ber_appsequence(6)
    pkt = [ next_msgid.to_ber, request ].to_ber_sequence
    write pkt

    (be = read) && (pdu = Net::LDAP::PDU.new(be)) && (pdu.app_tag == Net::LDAP::PDU::ModifyResponse) or raise Net::LDAP::LdapError, "response missing or invalid"

    pdu
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  # Unlike other operation-methods in this class, we return a result hash
  # rather than a simple result number. This is experimental, and eventually
  # we'll want to do this with all the others. The point is to have access
  # to the error message and the matched-DN returned by the server.
  #++
  def add(args)
    add_dn = args[:dn] or raise Net::LDAP::LdapError, "Unable to add empty DN"
    add_attrs = []
    a = args[:attributes] and a.each { |k, v|
      add_attrs << [ k.to_s.to_ber, Array(v).map { |m| m.to_ber}.to_ber_set ].to_ber_sequence
    }

    request = [add_dn.to_ber, add_attrs.to_ber_sequence].to_ber_appsequence(8)
    pkt = [next_msgid.to_ber, request].to_ber_sequence
    write pkt

    (be = read) &&
      (pdu = Net::LDAP::PDU.new(be)) &&
      (pdu.app_tag == Net::LDAP::PDU::AddResponse) or
      raise Net::LDAP::LdapError, "response missing or invalid"

    pdu
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  #++
  def rename(args)
    old_dn = args[:olddn] or raise "Unable to rename empty DN"
    new_rdn = args[:newrdn] or raise "Unable to rename to empty RDN"
    delete_attrs = args[:delete_attributes] ? true : false
    new_superior = args[:new_superior]

    request = [old_dn.to_ber, new_rdn.to_ber, delete_attrs.to_ber]
    request << new_superior.to_ber_contextspecific(0) unless new_superior == nil

    pkt = [next_msgid.to_ber, request.to_ber_appsequence(12)].to_ber_sequence
    write pkt

    (be = read) &&
    (pdu = Net::LDAP::PDU.new( be )) && (pdu.app_tag == Net::LDAP::PDU::ModifyRDNResponse) or
    raise Net::LDAP::LdapError.new( "response missing or invalid" )

    pdu
  end

  #--
  # TODO, need to support a time limit, in case the server fails to respond.
  #++
  def delete(args)
    dn = args[:dn] or raise "Unable to delete empty DN"
    controls = args.include?(:control_codes) ? args[:control_codes].to_ber_control : nil #use nil so we can compact later
    request = dn.to_s.to_ber_application_string(10)
    pkt = [next_msgid.to_ber, request, controls].compact.to_ber_sequence
    write pkt

    (be = read) && (pdu = Net::LDAP::PDU.new(be)) && (pdu.app_tag == Net::LDAP::PDU::DeleteResponse) or raise Net::LDAP::LdapError, "response missing or invalid"

    pdu
  end
end # class Connection
