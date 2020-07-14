class Net::LDAP
  # define Error as a module so that we can use it in exceptions derived from
  # other classes (e.g. Errno::ECONNREFUSED)
  module Error; end
  # define a base class for our "normal" errors
  class ErrorClass < StandardError;
    include Error
  end
  class AlreadyOpenedError < ErrorClass; end
  class SocketError < ErrorClass; end

  # make ConnectionRefusedError a kind of Errno::ECONNREFUSED
  # so that code looking for that exception will work correctly
  class ConnectionRefusedError < Errno::ECONNREFUSED
    include Error

    # don't print a deprication message on initialization or printing the message.
    # we control those, and code that is using the proper calls will still get the
    # warnings pointlessly.

    # display the deprication warning on === which will get called any time an exception
    # goes through a handler like
    # begin
    #   ...
    # rescue ConnectionRefusedError => e
    #   <handler code>
    # end
    #
    # which *is* the code we want people to stop using
    def self.===(val)
      warn_deprecation_message
      super
    end

    def self.warn_deprecation_message
      warn "Deprecation warning: Net::LDAP::ConnectionRefused will be deprecated. Use Errno::ECONNREFUSED instead."
    end
  end

  class ConnectionError < ErrorClass
    def self.new(errors)
      error = errors.first.first
      if errors.size == 1
        if error.kind_of? Errno::ECONNREFUSED
          return Net::LDAP::ConnectionRefusedError.new(error.message)
        end

        return Net::LDAP::ErrorClass.new(error.message)
      end

      super
    end

    def initialize(errors)
      message = "Unable to connect to any given server: \n  #{errors.map { |e, h, p| "#{e.class}: #{e.message} (#{h}:#{p})" }.join("\n  ")}"
      super(message)
    end
  end
  class NoOpenSSLError < ErrorClass; end
  class NoStartTLSResultError < ErrorClass; end
  class NoSearchBaseError < ErrorClass; end
  class StartTLSError < ErrorClass; end
  class EncryptionUnsupportedError < ErrorClass; end
  class EncMethodUnsupportedError < ErrorClass; end
  class AuthMethodUnsupportedError < ErrorClass; end
  class BindingInformationInvalidError < ErrorClass; end
  class NoBindResultError < ErrorClass; end
  class SASLChallengeOverflowError < ErrorClass; end
  class SearchSizeInvalidError < ErrorClass; end
  class SearchScopeInvalidError < ErrorClass; end
  class ResponseTypeInvalidError < ErrorClass; end
  class ResponseMissingOrInvalidError < ErrorClass; end
  class EmptyDNError < ErrorClass; end
  class HashTypeUnsupportedError < ErrorClass; end
  class OperatorError < ErrorClass; end
  class SubstringFilterError < ErrorClass; end
  class SearchFilterError < ErrorClass; end
  class BERInvalidError < ErrorClass; end
  class SearchFilterTypeUnknownError < ErrorClass; end
  class BadAttributeError < ErrorClass; end
  class FilterTypeUnknownError < ErrorClass; end
  class FilterSyntaxInvalidError < ErrorClass; end
  class EntryOverflowError < ErrorClass; end
end
