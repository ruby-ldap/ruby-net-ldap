# NET::BER
# Mixes ASN.1/BER convenience methods into several standard classes. Also
# provides BER parsing functionality.
#
#--
# Copyright (C) 2006 by Francis Cianfrocca and other contributors. All
# Rights Reserved.
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
#++

require 'net/ber/ber_parser'
class IO
  include Net::BER::BERParser
end

class StringIO
  include Net::BER::BERParser
end

if defined? ::OpenSSL
  class OpenSSL::SSL::SSLSocket
    include Net::BER::BERParser
  end
end

module Net::BER::Extensions; end

require 'net/ber/core_ext/string'
class String
  include Net::BER::BERParser
  include Net::BER::Extensions::String
end

require 'net/ber/core_ext/array'
class Array
  include Net::BER::Extensions::Array
end

require 'net/ber/core_ext/bignum'
class Bignum
  include Net::BER::Extensions::Bignum
end

require 'net/ber/core_ext/fixnum'
class Fixnum
  include Net::BER::Extensions::Fixnum
end

require 'net/ber/core_ext/true_class'
class TrueClass
  include Net::BER::Extensions::TrueClass
end

require 'net/ber/core_ext/false_class'
class FalseClass
  include Net::BER::Extensions::FalseClass
end
