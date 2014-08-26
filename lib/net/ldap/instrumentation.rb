module Net::LDAP::Instrumentation
  attr_reader :instrumentation_service
  private     :instrumentation_service

  # Internal: Instrument a block with the defined instrumentation service.
  #
  # Returns the return value of the block.
  def instrument(event, payload = {})
    return yield(payload) unless instrumentation_service

    instrumentation_service.instrument(event, payload) do |payload|
      payload[:result] = yield(payload)
    end
  end
  private :instrument
end
