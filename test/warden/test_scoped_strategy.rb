# frozen_string_literal: true

require "test_helper"
require "test_helper/webauthn_test_helpers"
require "rack/test"
require "rack"

class Warden::TestScopedStrategy < Minitest::Test
  include WebAuthnTestHelpers
  include Warden::Test::Helpers
  include Rack::Test::Methods

  class UserWebAuthnStrategy < Warden::WebAuthn::Strategy
    def authentication_challenge_key
      'user_current_webauthn_authentication_challenge'
    end

    def credential_finder_key
      'user_warden.webauthn.credential_finder'
    end

    def relying_party_key
      'user_warden.webauthn.relying_party'
    end
  end

  class AdminWebAuthnStrategy < Warden::WebAuthn::Strategy
    def authentication_challenge_key
      'admin_current_webauthn_authentication_challenge'
    end

    def credential_finder_key
      'admin_warden.webauthn.credential_finder'
    end

    def relying_party_key
      'admin_warden.webauthn.relying_party'
    end
  end

  class ScopedAuthenticationApp
    include WebAuthnTestHelpers
    include Warden::WebAuthn::AuthenticationInitiationHelpers
    include Warden::WebAuthn::StrategyHelpers
    attr_accessor :relying_party, :request, :client, :stored_credential, :scope

    def self.admin_instance
      @admin_instance ||= self.new(scope: :admin)
    end

    def self.user_instance
      @user_instance ||= self.new(scope: :user)
    end

    def initialize(scope:)
      self.relying_party = WebAuthn::RelyingParty.new(
        origin: "https://example.test",
        name: "Example Relying Party"
      )

      self.scope = scope
    end

    # Override to keep data isolated based on current scopes
    def authentication_challenge_key
      "#{scope}_current_webauthn_authentication_challenge"
    end

    def credential_finder_key
      "#{scope}_warden.webauthn.credential_finder"
    end

    def relying_party_key
      "#{scope}_warden.webauthn.relying_party"
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
        user: "Tester: #{self.scope}"
      )
    end

    def call(env)
      self.request = Rack::Request.new(env)

      env[relying_party_key] = self.relying_party
      env[credential_finder_key] = CredentialFinder.new(expected_stored_credential: self.stored_credential)

      case request.path
      when "/#{scope}/step1"
        options = generate_authentication_options(relying_party: relying_party)
        store_challenge_in_session(options_for_authentication: options)
        Rack::Response.new(JSON.generate(options.as_json)).finish
      when "/#{scope}/step2"
        env['warden'].authenticate!(scope: scope)
        response = Rack::Response.new
        response.redirect("/#{scope}/")
        response.finish
      else
        env['warden'].authenticate!(scope: scope)
        Rack::Response.new("OK: #{env['warden'].user(scope)}").finish
      end
    end

    class CredentialFinder
      attr_accessor :expected_stored_credential

      def initialize(expected_stored_credential:)
        self.expected_stored_credential = expected_stored_credential
      end


      def find_with_credential_id(encoded_credential_id)
        if encoded_credential_id == self.expected_stored_credential&.external_id
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
        Rack::Response.new("FAIL: #{env['warden'].errors.to_hash.to_json} #{env['warden.options']}", 500).finish
      end

      Warden::Strategies.add(:webauthn, UserWebAuthnStrategy)
      Warden::Strategies.add(:admin_webauthn, AdminWebAuthnStrategy)

      use Warden::Manager do |manager|
        manager.default_strategies :webauthn
        manager.failure_app = failure_app

        manager.default_scope = :user
        manager.scope_defaults :admin, strategies: [:admin_webauthn]
      end

      map '/admin' do
        run ScopedAuthenticationApp.admin_instance
      end

      map '/user' do
        run ScopedAuthenticationApp.user_instance
      end
    end
  end

  def teardown
    Warden::Strategies.clear!
    Warden.test_reset!
  end

  def user_authentication_app
    ScopedAuthenticationApp.user_instance
  end

  def admin_authentication_app
    ScopedAuthenticationApp.admin_instance
  end

  def assert_user_authenticated?
    assert_equal true, last_request.env['warden'].authenticated?(:user)
  end

  def assert_admin_authenticated?
    assert_equal true, last_request.env['warden'].authenticated?(:admin)
  end

  def assert_user_not_authenticated?
    assert_equal false, last_request.env['warden'].authenticated?(:user)
  end

  def assert_admin_not_authenticated?
    assert_equal false, last_request.env['warden'].authenticated?(:admin)
  end

  def assert_user_session_challenge_equal(expected:)
    assert_equal expected, last_request.session["user_current_webauthn_authentication_challenge"]
  end

  def assert_admin_session_challenge_equal(expected:)
    assert_equal expected, last_request.session["admin_current_webauthn_authentication_challenge"]
  end

  def assert_user_session_challenge_nil
    assert_nil last_request.session["user_current_webauthn_authentication_challenge"]
  end

  def assert_admin_session_challenge_nil
    assert_nil last_request.session["admin_current_webauthn_authentication_challenge"]
  end

  def build_uri(authentication_app:, path:)
    uri = URI(authentication_app.relying_party.origin)
    uri.path = path
  end

  def test_user_authentication
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    assertion = assertion_from_client(client: user_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step2"), {credential: JSON.generate(assertion) })

    assert last_response.redirect?
    assert_equal "/user/", last_response.location
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/user"))

    assert last_response.ok?
    assert_equal "OK: Tester: user", last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_authenticated?
    assert_admin_not_authenticated?
  end

  def test_admin_authentication
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil
    assertion = assertion_from_client(client: admin_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step2"), {credential: JSON.generate(assertion) })

    assert last_response.redirect?
    assert_equal "/admin/", last_response.location
    assert_admin_session_challenge_nil
    assert_user_session_challenge_nil

    get(build_uri(authentication_app: admin_authentication_app, path: "/admin"))

    assert last_response.ok?
    assert_equal "OK: Tester: admin", last_response.body

    assert_admin_session_challenge_nil
    assert_user_session_challenge_nil

    assert_admin_authenticated?
    assert_user_not_authenticated?
  end

  def test_simultaneous_authentication
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    user_challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: user_challenge_json["challenge"])
    assert_admin_session_challenge_nil

    post(build_uri(authentication_app: user_authentication_app, path: "/admin/step1"))

    assert last_response.ok?

    admin_challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: user_challenge_json["challenge"])
    assert_admin_session_challenge_equal(expected: admin_challenge_json["challenge"])

    user_assertion = assertion_from_client(client: user_authentication_app.client, challenge: user_challenge_json["challenge"], user_verified: true)
    admin_assertion = assertion_from_client(client: admin_authentication_app.client, challenge: admin_challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step2"), {credential: JSON.generate(user_assertion) })

    assert last_response.redirect?
    assert_equal "/user/", last_response.location
    assert_user_session_challenge_nil
    assert_admin_session_challenge_equal(expected: admin_challenge_json["challenge"])


    post(build_uri(authentication_app: user_authentication_app, path: "/admin/step2"), {credential: JSON.generate(admin_assertion) })

    assert last_response.redirect?
    assert_equal "/admin/", last_response.location
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/user"))

    assert last_response.ok?
    assert_equal "OK: Tester: user", last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_authenticated?
    assert_admin_authenticated?

    get(build_uri(authentication_app: user_authentication_app, path: "/admin"))

    assert last_response.ok?
    assert_equal "OK: Tester: admin", last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_authenticated?
    assert_admin_authenticated?
  end

  def test_user_credential_cannot_be_used_for_admin
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil
    assertion = assertion_from_client(client: user_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"stored_credential":["not_found"]} {:scope=>:admin, :action=>"unauthenticated", :message=>:stored_credential_not_found, :attempted_path=>"/admin/step2"}', last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil


    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_user_challenge_cannot_be_used_for_admin
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil
    assertion = assertion_from_client(client: user_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"stored_credential":["not_found"]} {:scope=>:admin, :action=>"unauthenticated", :message=>:stored_credential_not_found, :attempted_path=>"/admin/step2"}', last_response.body
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil


    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_admin_credential_cannot_be_used_for_user
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil
    assertion = assertion_from_client(client: admin_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"stored_credential":["not_found"]} {:scope=>:user, :action=>"unauthenticated", :message=>:stored_credential_not_found, :attempted_path=>"/user/step2"}', last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_user_not_verified
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    assertion = assertion_from_client(client: user_authentication_app.client, challenge: challenge_json["challenge"], user_verified: false)

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {} {:scope=>:user, :action=>"unauthenticated", :message=>:webauthn_user_verified_verification_error, :attempted_path=>"/user/step2"}', last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/user"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:user, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/user"}', last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_user_bad_challenge
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    assertion = assertion_from_client(client: user_authentication_app.client, challenge: encode_challenge, user_verified: true)

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {} {:scope=>:user, :action=>"unauthenticated", :message=>:webauthn_challenge_verification_error, :attempted_path=>"/user/step2"}', last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/user"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:user, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/user"}', last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_user_already_authenticated
    login_as "Tester: user", scope: :user
    get(build_uri(authentication_app: user_authentication_app, path: "/user"))

    assert last_response.ok?
    assert_equal "OK: Tester: user", last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_authenticated?
    assert_admin_not_authenticated?
  end

  def test_user_credential_removed
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    assertion = assertion_from_client(client: user_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    user_authentication_app.stored_credential = nil

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"stored_credential":["not_found"]} {:scope=>:user, :action=>"unauthenticated", :message=>:stored_credential_not_found, :attempted_path=>"/user/step2"}', last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/user"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:user, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/user"}', last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_user_credential_missing
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    assertion = assertion_from_client(client: user_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step2"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:user, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/user/step2"}', last_response.body
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/user"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:user, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/user"}', last_response.body

    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_user_credential_cannot_be_parsed
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    assertion = assertion_from_client(client: user_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: user_authentication_app, path: "/user/step2"), {credential: "asdasdasd" })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["json_error"]} {:scope=>:user, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/user/step2"}', last_response.body
    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/user"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:user, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/user"}', last_response.body

    assert_user_session_challenge_equal(expected: challenge_json["challenge"])
    assert_admin_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end


  def test_admin_not_verified
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    assertion = assertion_from_client(client: admin_authentication_app.client, challenge: challenge_json["challenge"], user_verified: false)

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {} {:scope=>:admin, :action=>"unauthenticated", :message=>:webauthn_user_verified_verification_error, :attempted_path=>"/admin/step2"}', last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/admin"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:admin, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/admin"}', last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_admin_bad_challenge
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    assertion = assertion_from_client(client: admin_authentication_app.client, challenge: encode_challenge, user_verified: true)

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {} {:scope=>:admin, :action=>"unauthenticated", :message=>:webauthn_challenge_verification_error, :attempted_path=>"/admin/step2"}', last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/admin"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:admin, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/admin"}', last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_admin_already_authenticated
    login_as "Tester: admin", scope: :admin
    get(build_uri(authentication_app: admin_authentication_app, path: "/admin"))

    assert last_response.ok?
    assert_equal "OK: Tester: admin", last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_admin_authenticated?
    assert_user_not_authenticated?
  end

  def test_admin_credential_removed
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    assertion = assertion_from_client(client: admin_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    admin_authentication_app.stored_credential = nil

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step2"), {credential: JSON.generate(assertion) })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"stored_credential":["not_found"]} {:scope=>:admin, :action=>"unauthenticated", :message=>:stored_credential_not_found, :attempted_path=>"/admin/step2"}', last_response.body
    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    get(build_uri(authentication_app: admin_authentication_app, path: "/admin"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:admin, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/admin"}', last_response.body

    assert_user_session_challenge_nil
    assert_admin_session_challenge_nil

    assert_admin_not_authenticated?
    assert_user_not_authenticated?
  end

  def test_admin_credential_missing
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    assertion = assertion_from_client(client: admin_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step2"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:admin, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/admin/step2"}', last_response.body
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/admin"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:admin, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/admin"}', last_response.body

    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end

  def test_admin_credential_cannot_be_parsed
    admin_authentication_app.create_and_store_credential
    user_authentication_app.create_and_store_credential

    post(build_uri(authentication_app: admin_authentication_app, path: "/admin/step1"))

    assert last_response.ok?

    challenge_json = JSON.parse(last_response.body)
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    assertion = assertion_from_client(client: user_authentication_app.client, challenge: challenge_json["challenge"], user_verified: true)

    post(build_uri(authentication_app: user_authentication_app, path: "/admin/step2"), {credential: "asdasdasd" })

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["json_error"]} {:scope=>:admin, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/admin/step2"}', last_response.body
    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    get(build_uri(authentication_app: user_authentication_app, path: "/admin"))

    assert_equal 500, last_response.status
    assert_equal 'FAIL: {"credential":["missing"]} {:scope=>:admin, :action=>"unauthenticated", :message=>nil, :attempted_path=>"/admin"}', last_response.body

    assert_admin_session_challenge_equal(expected: challenge_json["challenge"])
    assert_user_session_challenge_nil

    assert_user_not_authenticated?
    assert_admin_not_authenticated?
  end
end