# frozen_string_literal: true

module Warden
  module WebAuthn
    # Helper methods to bootstrap registration challenges for implementors
    module RegistrationHelpers
      def generate_registration_options(relying_party:, user_details:, exclude: [], options: {})
        relying_party.options_for_registration(**{
          user: user_details,
          exclude: exclude,
          authenticator_selection: { user_verification: "required" }
        }.merge(options))
      end

      def store_challenge_in_session(options_for_registration:)
        session[registration_challenge_key] = options_for_registration.challenge
      end

      def verify_registration(relying_party:)
        relying_party.verify_registration(
          parsed_credential, registration_challenge, user_verification: true
        )
      ensure
        delete_registration_challenge
      end

      def registration_challenge
        session[registration_challenge_key]
      end

      def delete_registration_challenge
        session.delete(registration_challenge_key)
      end

      def parsed_credential
        JSON.parse(raw_credential)
      end

      def raw_credential
        params[raw_credential_key]
      end

      def raw_credential_key
        "credential"
      end

      def registration_challenge_key
        "current_webauthn_registration_challenge"
      end
    end
  end
end
