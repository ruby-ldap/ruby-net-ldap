require 'stringio'
require 'openssl'
require 'socket'
require 'ostruct'
require 'base64'
require 'strscan'

if RUBY_VERSION =~ /^1.9/
  begin
    SHA1
  rescue NameError
    require 'digest/sha1'
    SHA1 = Digest::SHA1
  end
  
  begin
    MD5
  rescue NameError
    require 'digest/md5'
    MD5 = Digest::MD5
  end  
end

if RUBY_VERSION =~ /^1.8/
  require 'md5'
  require 'sha1'
end

module Net
  autoload :BER, 'net/ber'
  autoload :LDAP, 'net/ldap'
  autoload :LDIF, 'net/ldif'
  autoload :SNMP, 'net/snmp'
  module BER
    autoload :BERParser, 'net/ber/ber_parser'
  end 
end
require 'net/ldap/core_ext/all'