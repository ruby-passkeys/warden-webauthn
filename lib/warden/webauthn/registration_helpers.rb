module Warden
  module WebAuthn
    module RegistrationHelpers
      def generate_registration_options(relying_party:, user_details:, exclude: [], options: {})
        return relying_party.options_for_registration(**{
          user: user_details,
          exclude: exclude,
          authenticator_selection: { user_verification: "required" }
        }.merge(options))
      end

      def store_challenge_in_session(options_for_registration:)
        session[registration_challenge_key] = options_for_registration.challenge
      end

      def registration_challenge_key
        'current_webauthn_registration_challenge'
      end
    end
  end
end