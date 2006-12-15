# $Id$
#
# NET::SNMP
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
#

require 'net/ber'


module Net

    class SNMP

	AsnSyntax = BER.compile_syntax({
	    :application => {
		:primitive => {
		},
		:constructed => {
		}
	    },
	    :context_specific => {
		:primitive => {
		},
		:constructed => {
		    0 => :array		# GetRequest PDU (RFC1157 pgh 4.1.2)
		}
	    }
	})

    end

    class SnmpPdu
	class Error < Exception; end

	attr_reader :version, :community, :pdu_type, :request_id, :variables

	#--
	# TODO, improve the error-trapping.
	# We want to wrap up Ruby errors like array-ranges, which can appear if we get bad data.
	# We should probably do the whole parse under a catch-all block.
	def initialize ber_object
	    begin
		parse_ber_object ber_object
	    rescue RuntimeError
		# Wrap any basic parsing error so it becomes a PDU-format error
		raise Error.new( "snmp-pdu format error" )
	    end
	end

	def parse_ber_object ber_object
	    @version = ber_object[0].to_i
	    unless [0,2].include?(@version)
		raise Error.new("unknown snmp-version: #{@version}")
	    end

	    @community = ber_object[1].to_s

	    data = ber_object[2]
	    app_tag = data.ber_identifier & 31
	    case app_tag
	    when 0
		@pdu_type = :get_request
		parse_get_request data
	    else
		raise Error.new( "unknown snmp-pdu type: #{app_tag}" )
	    end
	end

	#--
	# Defined in RFC1157, pgh 4.1.2.
	def parse_get_request data
	    @request_id = data[0].to_i
	    # data[1] is error-status, always 0.
	    # data[2] is error-index, always 0.
	    @variables = data[3].map {|v|
		# A variable-binding, of which there may be several,
		# consists of an OID and a BER null.
		# We're ignoring the null, we might want to verify it instead.
		v[0]
	    }
	end

    end
end

