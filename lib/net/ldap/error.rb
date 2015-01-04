class Net::LDAP
  class Error < StandardError; end

  class AlreadyOpenedError < Error; end
  class SocketError < Error; end
  class ConnectionRefusedError < Error; end
  class NoOpenSSLError < Error; end
  class NoStartTLSResultError < Error; end
  class StartTLSError < Error; end
  class EncryptionUnsupportedError < Error; end
  class EncMethodUnsupportedError < Error; end
  class AuthMethodUnsupportedError < Error; end
  class BindingInformationInvalidError < Error; end
  class NoBindResultError < Error; end
  class SASLChallengeOverflowError < Error; end
  class SearchSizeInvalidError < Error; end
  class SearchScopeInvalidError < Error; end
  class ResponseTypeInvalidError < Error; end
  class ResponseMissingOrInvalidError < Error; end
  class EmptyDNError < Error; end
  class HashTypeUnsupportedError < Error; end
  class OperatorError < Error; end
  class SubstringFilterError < Error; end
  class SearchFilterError < Error; end
  class BERInvalidError < Error; end
  class SearchFilterTypeUnknownError < Error; end
  class BadAttributeError < Error; end
  class FilterTypeUnknownError < Error; end
  class FilterSyntaxInvalidError < Error; end
  class EntryOverflowError < Error; end
end
