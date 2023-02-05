# frozen_string_literal: true

require "test_helper"
require "test_helper/webauthn_test_helpers"
require "rack/test"
require "rack"

class Warden::TestStrategy < Minitest::Test
  include WebAuthnTestHelpers
  include Warden::Test::Helpers
  include Rack::Test::Methods

  class AuthenticationApp
    include WebAuthnTestHelpers
    include Warden::WebAuthn::AuthenticationInitiationHelpers
    include Warden::WebAuthn::StrategyHelpers
    attr_accessor :relying_party, :request, :client, :stored_credential

    def self.instance
      @instance ||= self.new
    end

    def initialize
      self.relying_party = WebAuthn::RelyingParty.new(
        origin: "https://example.test",
        name: "Example Relying Party"
      )
    end

    def session
      self.request.session
    end

    def create_and_store_credential
      self.client = fake_client(origin: relying_party.origin)
      credential = create_credential(client: client, relying_party: relying_party)
      self.stored_credential = OpenStruct.new(
        external_id: Base64.strict_encode64(credential.id),
        public_key: relying_party.encoder.encode(credential.public_key),
        user: "Tester"
      )
    end

    def call(env)
      self.request = Rack::Request.new(env)

      env[relying_party_key] = self.relying_party
      env[credential_finder_key] = CredentialFinder.new(expected_stored_credential: self.stored_credential)

      case request.path
      when "/step1"
        options = generate_authentication_options(relying_party: relying_party)
        store_challenge_in_session(options_for_authentication: options)
        Rack::Response.new(JSON.generate(options.as_json)).finish
      when "/step2"
        env['warden'].authenticate!
        response = Rack::Response.new
        response.redirect("/")
        response.finish
      else
        env['warden'].authenticate!
        Rack::Response.new("OK: #{env['warden'].user}").finish
      end
    end

    class CredentialFinder
      attr_accessor :expected_stored_credential

      def initialize(expected_stored_credential:)
        self.expected_stored_credential = expected_stored_credential
      end


      def find_with_credential_id(encoded_credential_id)
        if encoded_credential_id == self.expected_stored_credential.external_id
          return expected_stored_credential
        else
          return nil
        end
      end
    end
  end

  def app
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: "a" * 64

      failure_app = lambda do |env|
        debugger
        Rack::Response.new("FAIL: #{env['warden'].errors.to_hash.to_json}", 500).finish
      end

      Warden::Strategies.add(:webauthn, Warden::WebAuthn::Strategy)

      use Warden::Manager do |manager|
        manager.default_strategies :webauthn
        manager.failure_app = failure_app
      end

      run AuthenticationApp.instance
    end
  end

  def teardown
    Warden::Strategies.clear!
    Warden.test_reset!
  end

  def authentication_app
    AuthenticationApp.instance
  end

  def build_uri(path)
    uri = URI(authentication_app.relying_party.origin)
    uri.path = path
  end


  def test_authentication
    authentication_app.create_and_store_credential

    post(build_uri("/step1"))
    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assertion = assertion_from_client(client: authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri("/step2"), {credential: JSON.generate(assertion) })

    assert last_response.redirect?
    assert_equal "/", last_response.location

    get(build_uri("/"))

    assert last_response.ok?
    assert_equal "OK: Tester", last_response.body
  end
end