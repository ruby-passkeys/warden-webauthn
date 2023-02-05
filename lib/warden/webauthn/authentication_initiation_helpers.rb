module Warden
  module WebAuthn
    module AuthenticationInitiationHelpers
      def generate_authentication_options(relying_party:, options: {})
        return relying_party.options_for_authentication(
          {user_verification: "required"}.merge(options)
        )
      end

      def store_challenge_in_session(options_for_authentication:)
        session[authentication_challenge_key] = options_for_authentication.challenge
      end

      def authentication_challenge_key
        'current_webauthn_authentication_challenge'
      end
    end
  end
end