# -*- ruby encoding: utf-8 -*-
require 'digest/sha1'
require 'digest/md5'
require 'base64'
require 'securerandom'

class Net::LDAP::Password
  class << self
    KNOWN = [:md5, :sha, :sha1, :sha256, :sha384, :sha512]
    # Generate a password-hash suitable for inclusion in an LDAP attribute.
    # Pass a hash type as a symbol (:md5, :sha, :ssha) and a plaintext
    # password. This function will return a hashed representation.
    #
    #--
    # STUB: This is here to fulfill the requirements of an RFC, which
    # one?
    def generate(type, str)
      if KNOWN.include?(type)
        digest = type.to_s
        salt = ''
      elsif type[0] == 's' && KNOWN.include?(type[1..-1].to_sym)
        digest = type[1..-1]
        salt = SecureRandom.random_bytes(16)
      else
        fail Net::LDAP::HashTypeUnsupportedError,
             "Unsupported password-hash type (#{type})"
      end
      digest = 'sha1' if digest == 'sha'
      type = (type == :sha1 ? :sha : :ssha) if type[-4, 4] == 'sha1'
      algo = Digest.module_eval(digest.upcase)
      "{#{type.upcase}}#{Base64.encode64(algo.digest(str + salt) + salt).chomp}"
    end
  end
end
