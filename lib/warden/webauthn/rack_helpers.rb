# frozen_string_literal: true

module Warden
  module WebAuthn
    # Helpers that can be mixed in to any Rack middleware or application, in order
    # to setup the environment for `Warden::WebAuthn`, such as the Relying Party
    module RackHelpers
      def relying_party_key
        "warden.webauthn.relying_party"
      end

      def set_relying_party_in_request_env
        request.env[relying_party_key] = relying_party
      end
    end
  end
end
