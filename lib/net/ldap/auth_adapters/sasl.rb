require 'net/ldap/auth_adapter'

module Net
  class LDAP
    module AuthAdapters
      class Sasl < Net::LDAP::AuthAdapter
        def bind(auth)
          mech, cred, chall = auth[:mechanism], auth[:initial_credential],
            auth[:challenge_response]
          raise Net::LDAP::BindingInformationInvalidError, "Invalid binding information" unless (mech && cred && chall)

          message_id = @connection.next_msgid

          n = 0
          loop {
            sasl = [mech.to_ber, cred.to_ber].to_ber_contextspecific(3)
            request = [
              Net::LDAP::Connection::LdapVersion.to_ber, "".to_ber, sasl
            ].to_ber_appsequence(Net::LDAP::PDU::BindRequest)

            @connection.send(:write, request, nil, message_id)
            pdu = @connection.queued_read(message_id)

            if !pdu || pdu.app_tag != Net::LDAP::PDU::BindResult
              raise Net::LDAP::NoBindResultError, "no bind result"
            end

            return pdu unless pdu.result_code == Net::LDAP::ResultCodeSaslBindInProgress
            raise Net::LDAP::SASLChallengeOverflowError, "sasl-challenge overflow" if ((n += 1) > MaxSaslChallenges)

            cred = chall.call(pdu.result_server_sasl_creds)
          }

          raise Net::LDAP::SASLChallengeOverflowError, "why are we here?"
        end
      end
    end
  end
end

Net::LDAP::AuthAdapter.register(:sasl, Net::LDAP::AuthAdapters::Sasl)
