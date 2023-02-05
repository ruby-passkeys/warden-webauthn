require "webauthn/fake_client"

module WebAuthnTestHelpers
  def example_relying_party(options: {})
    return WebAuthn::RelyingParty.new(**{
      origin: "https://example.test",
      name: "Example Relying Party"
    }.merge(options))
  end

  def fake_client(origin: "https://example.test")
    return WebAuthn::FakeClient.new(origin)
  end
end