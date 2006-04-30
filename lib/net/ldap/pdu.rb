# $Id$
#
# LDAP PDU support classes
#
#
#----------------------------------------------------------------------------
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
#---------------------------------------------------------------------------
#



module Net


class LdapPduError < Exception; end


class LdapPdu

  BindResult = 1
  SearchReturnedData = 4
  SearchResult = 5
  ModifyResponse = 7
  AddResponse = 9
  DeleteResponse = 11
  ModifyRDNResponse = 13

  attr_reader :msg_id, :app_tag
  attr_reader :search_dn, :search_attributes, :search_entry

  #
  # initialize
  # An LDAP PDU always looks like a BerSequence with
  # two elements: an integer (message-id number), and
  # an application-specific sequence.
  # The application-specific tag in the sequence tells
  # us what kind of packet it is, and each kind has its
  # own format, defined in RFC-1777.
  # Observe that many clients (such as ldapsearch)
  # do not necessarily enforce the expected application
  # tags on received protocol packets. This implementation
  # does interpret the RFC strictly in this regard, and
  # it remains to be seen whether there are servers out
  # there that will not work well with our approach.
  #
  def initialize ber_object
    begin
      @msg_id = ber_object[0].to_i
      @app_tag = ber_object[1].ber_identifier - 0x60
    rescue
      # any error becomes a data-format error
      raise LdapPduError.new( "ldap-pdu format error" )
    end

    case @app_tag
    when BindResult
      parse_ldap_result ber_object[1]
    when SearchReturnedData
      parse_search_return ber_object[1]
    when SearchResult
      parse_ldap_result ber_object[1]
    when ModifyResponse
      parse_ldap_result ber_object[1]
    when AddResponse
      parse_ldap_result ber_object[1]
    when DeleteResponse
      parse_ldap_result ber_object[1]
    when ModifyRDNResponse
      parse_ldap_result ber_object[1]
    else
      raise LdapPduError.new( "unknown pdu-type: #{@app_tag}" )
    end
  end

  #
  # result_code
  # This returns an LDAP result code taken from the PDU,
  # but it will be nil if there wasn't a result code.
  # That can easily happen depending on the type of packet.
  #
  def result_code code = :resultCode
    @ldap_result and @ldap_result[code]
  end


  private

  #
  # parse_ldap_result
  #
  def parse_ldap_result sequence
    sequence.length >= 3 or raise LdapPduError
    @ldap_result = {:resultCode => sequence[0], :matchedDN => sequence[1], :errorMessage => sequence[2]}
  end

  #
  # parse_search_return
  # Definition from RFC 1777 (we're handling application-4 here)
  #
  # Search Response ::=
  #    CHOICE {
  #         entry          [APPLICATION 4] SEQUENCE {
  #                             objectName     LDAPDN,
  #                             attributes     SEQUENCE OF SEQUENCE {
  #                                                 AttributeType,
  #                                                 SET OF AttributeValue
  #                                            }
  #                        },
  #         resultCode     [APPLICATION 5] LDAPResult
  #     }
  #
  # We concoct a search response that is a hash of the returned attribute values.
  # NOW OBSERVE CAREFULLY: WE ARE DOWNCASING THE RETURNED ATTRIBUTE NAMES.
  # This is to make them more predictable for user programs, but it
  # may not be a good idea. Maybe this should be configurable.
  # ALTERNATE IMPLEMENTATION: In addition to @search_dn and @search_attributes,
  # we also return @search_entry, which is an LDAP::Entry object.
  # If that works out well, then we'll remove the first two.
  #
  def parse_search_return sequence
    sequence.length >= 2 or raise LdapPduError
    @search_entry = LDAP::Entry.new( sequence[0] )
    @search_dn = sequence[0]
    @search_attributes = {}
    sequence[1].each {|seq|
      @search_entry[seq[0]] = seq[1]
      @search_attributes[seq[0].downcase.intern] = seq[1]
    }
  end


end


end # module Net

