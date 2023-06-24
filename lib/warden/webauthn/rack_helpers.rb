module Warden
  module WebAuthn
    module RackHelpers
      def relying_party_key
        "warden.webauthn.relying_party"
      end
    end
  end
end
