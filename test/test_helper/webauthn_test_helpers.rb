module WebAuthnTestHelpers
  def example_relying_party(options: {})
    return WebAuthn::RelyingParty.new(**{
      origin: "https://example.test",
      name: "Example Relying Party"
    }.merge(options))
  end
end