require 'net/ldap/auth_adapter'

module Net
  class LDAP
    module AuthAdapters
      class Simple < AuthAdapter
        def bind(auth)
          user, psw = if auth[:method] == :simple
                        [auth[:username] || auth[:dn], auth[:password]]
                      else
                        ["", ""]
                      end

          raise Net::LDAP::BindingInformationInvalidError, "Invalid binding information" unless (user && psw)

          message_id = @connection.next_msgid
          request    = [
            LdapVersion.to_ber, user.to_ber,
            psw.to_ber_contextspecific(0)
          ].to_ber_appsequence(Net::LDAP::PDU::BindRequest)

          @connection.write(request, nil, message_id)
          pdu = @connection.queued_read(message_id)

          if !pdu || pdu.app_tag != Net::LDAP::PDU::BindResult
            raise Net::LDAP::NoBindResultError, "no bind result"
          end

          pdu
        end
      end
    end
  end
end

Net::LDAP::AuthAdapter.register(:simple, Net::LDAP::AuthAdapters::Simple)
