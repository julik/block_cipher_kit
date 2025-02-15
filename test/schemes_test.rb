# frozen_string_literal: true

require_relative "test_helper"

class SchemesTest < Minitest::Test
  [
    "BlockCipherKit::PassthruScheme",
    "BlockCipherKit::AES256CFBScheme",
    "BlockCipherKit::AES256CTRScheme",
    "BlockCipherKit::AES256GCMScheme",
    "BlockCipherKit::AES256CBCScheme"
  ].each do |scheme_class_name|
    define_method "test_scheme #{scheme_class_name} encrypts and decrypts correctly, including random access" do
      assert_encrypts_from_block_and_io(scheme_class_name)
      assert_decrypts_into_block_and_io(scheme_class_name)
      assert_correct_readback(scheme_class_name)
    end
  end

  [
    "BlockCipherKit::AES256CFBScheme",
    "BlockCipherKit::AES256CTRScheme",
    "BlockCipherKit::AES256GCMScheme",
    "BlockCipherKit::AES256CBCScheme"
  ].each do |scheme_class_name|
    define_method("test_scheme #{scheme_class_name} provides different ciphertext depending on key") do
      assert_key_changes_ciphertext(scheme_class_name)
    end
  end

  [
    "BlockCipherKit::AES256CFBScheme",
    "BlockCipherKit::AES256CTRScheme",
    "BlockCipherKit::AES256GCMScheme",
    "BlockCipherKit::AES256CBCScheme"
  ].each do |scheme_class_name|
    define_method "test_scheme #{scheme_class_name} fails to initialise with a key too small" do
      tiny_key = Random.new.bytes(3)
      assert_raises(ArgumentError) do
        resolve(scheme_class_name).new(tiny_key)
      end
    end
  end

  [
    "BlockCipherKit::AES256CFBScheme",
    "BlockCipherKit::AES256CTRScheme",
    "BlockCipherKit::AES256GCMScheme",
    "BlockCipherKit::AES256CBCScheme"
  ].each do |scheme_class_name|
    define_method "test_scheme #{scheme_class_name} does not expose key material in #inspect" do
      big_key = "wonderful and incredible easiness of being, combined with unearthly pleasures"
      inspectable = resolve(scheme_class_name).new(big_key).inspect
      big_key.split(/\s/).each do |word|
        refute inspectable.include?(word), "#inspect must not reveal key material"
      end
    end
  end

  def assert_key_changes_ciphertext(scheme_class_name)
    rng = Random.new(Minitest.seed)
    keys = 4.times.map { rng.bytes(64) }

    n_bytes = rng.rand(129..2048)
    plaintext = rng.bytes(n_bytes)

    ciphertexts = keys.map do |k|
      scheme = resolve(scheme_class_name).new(k)
      encrypted_io = StringIO.new.binmode
      scheme.streaming_encrypt(from_plaintext_io: StringIO.new(plaintext).binmode, into_ciphertext_io: encrypted_io)
      encrypted_io.string
    end

    assert_equal ciphertexts.length, ciphertexts.uniq.length
  end

  def assert_encrypts_from_block_and_io(scheme_class_name)
    rng = Random.new(Minitest.seed)
    encryption_key = rng.bytes(64)

    scheme = resolve(scheme_class_name).new(encryption_key)

    # Generate a prime number of bytes, so that the plaintext does not
    # subdivide into blocks. This will allow us to find situations where
    # block offsets are not used for reading.
    plaintext = rng.bytes(OpenSSL::BN.generate_prime(12))

    out1 = StringIO.new
    scheme.streaming_encrypt(into_ciphertext_io: out1) do |writable|
      writable.write(plaintext.byteslice(0, 417))
      writable.write(plaintext.byteslice(417, plaintext.bytesize))
    end
    assert out1.size > 0

    out2 = StringIO.new
    scheme.streaming_encrypt(from_plaintext_io: StringIO.new(plaintext), into_ciphertext_io: out2)
    assert out2.size > 0

    assert_equal out1.string, out2.string
  end

  def assert_decrypts_into_block_and_io(scheme_class_name)
    rng = Random.new(Minitest.seed)
    encryption_key = rng.bytes(64)

    scheme = resolve(scheme_class_name).new(encryption_key)

    # Generate a prime number of bytes, so that the plaintext does not
    # subdivide into blocks. This will allow us to find situations where
    # block offsets are not used for reading.
    plaintext = rng.bytes(OpenSSL::BN.generate_prime(12))
    ciphertext_io = StringIO.new
    scheme.streaming_encrypt(into_ciphertext_io: ciphertext_io, from_plaintext_io: StringIO.new(plaintext))

    ciphertext_io.rewind
    readback = StringIO.new.binmode
    scheme.streaming_decrypt(from_ciphertext_io: ciphertext_io, into_plaintext_io: readback)
    assert_equal readback.size, plaintext.bytesize
    assert_equal readback.string[0..16], plaintext[0..16]
    assert_equal readback.string[-4..], plaintext[-4..]

    ciphertext_io.rewind
    readback = StringIO.new.binmode
    scheme.streaming_decrypt(from_ciphertext_io: ciphertext_io) do |chunk|
      readback.write(chunk)
    end
    assert_equal readback.size, plaintext.bytesize
    assert_equal readback.string[0..16], plaintext[0..16]
    assert_equal readback.string[-4..], plaintext[-4..]
  end

  def assert_correct_readback(scheme_class_name)
    rng = Random.new(Minitest.seed)
    random_encryption_key = rng.bytes(64)

    enc = resolve(scheme_class_name).new(random_encryption_key)

    # Generate a prime number of bytes, so that the plaintext does not
    # subdivide into blocks. This will allow us to find situations where
    # block offsets are not used for reading. A 24-bit prime we get is
    # 14896667, which is just over 14 megabytes
    amount_of_plain_bytes = OpenSSL::BN.generate_prime(24).to_i
    plain_bytes = rng.bytes(amount_of_plain_bytes)

    source_io = StringIO.new(plain_bytes)
    enc_io = StringIO.new.binmode
    enc_io.write("HDR") # emulate a header
    enc.streaming_encrypt(from_plaintext_io: source_io, into_ciphertext_io: enc_io)

    enc_io.seek(3) # Move to the offset where ciphertext starts

    ranges = [
      0..0, # The first byte
      2..71, # Bytes that overlap block boundaries
      78..91, # A random located byte
      (amount_of_plain_bytes - 1)..(amount_of_plain_bytes - 1), # The last byte
      0..(amount_of_plain_bytes - 1) # The entire monty, but via ranges
    ]
    ranges += 8.times.map do
      r_begin = rng.rand(0..(amount_of_plain_bytes - 1))
      n_bytes = rng.rand(1..1204)
      r_begin..(r_begin + n_bytes)
    end

    ranges.each do |range|
      enc_io.seek(3) # Emulate the header already did get read

      expected = plain_bytes[range]
      next unless expected

      got = enc.decrypt_range(from_ciphertext_io: enc_io, range: range)

      assert got, "#{scheme_class_name} Range #{range} should have been decrypted but no bytes were output"
      assert_equal expected.bytesize, got.bytesize, "#{scheme_class_name} Range #{range} should have decrypted #{expected.bytesize} bytes but decrypted #{got.bytesize}"
      assert_equal expected, got, "#{scheme_class_name} Range #{range} bytes mismatch (#{expected[0..16].inspect} expected but #{got[0..16].inspect} decrypted"
    end

    enc_io.seek(3) # Emulate the header already did get read
    decrypted_io = StringIO.new.binmode
    enc.streaming_decrypt(from_ciphertext_io: enc_io, into_plaintext_io: decrypted_io)
    assert_equal decrypted_io.size, source_io.size, "#{scheme_class_name} should have decrypted the entire message"
    assert_equal plain_bytes, decrypted_io.string, "#{scheme_class_name} Bytes mismatch when decrypting the entire message"
  end

  def resolve(module_name)
    module_name.split("::").reduce(Kernel) do |namespace, const_name|
      namespace.const_get(const_name)
    end
  end
end
