# http://tools.ietf.org/html/rfc4511#section-4.5.1
class Net::LDAP::SearchRequest
  # TODO: docs
  # base_object
  # scope
  # deref_aliases
  # size_limit
  # time_limit
  # types_only
  # filter
  # attributes
  def initialize(args = {})
    @base_object = args[:base_object]
    @scope = args[:scope]
    @deref_aliases = args[:deref_aliases]
    @size_limit = args[:size_limit]
    @time_limit = args[:time_limit]
    @types_only = args[:types_only]
    @filter = args[:filter]
    @attributes = args[:attributes]
  end

  # Returns BER encoded string
  def to_ber
    [
      @base_object.to_ber,
      @scope.to_ber_enumerated,
      @deref_aliases.to_ber_enumerated,
      @size_limit.to_ber,
      @time_limit.to_ber,
      @types_only.to_ber,
      @filter.to_ber,
      @attributes.to_ber_sequence
    ].to_ber_appsequence(3)
  end
end
