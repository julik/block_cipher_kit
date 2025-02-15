require_relative "test_helper"

class TestKnownCiphertext < Minitest::Test
  PREAMBLE = <<~ERR
    This file is used as known plaintext for testing encryption schemes.
    It is designed to be a decent input harness: its size in bytes is a prime,
    so it will require padding to be produced if a cipher needs padding, and it
    will not subdivide into any standard block sizes. The subsequent content is
    not a hoax or a spoof. Bytes following this line are generated using the
    Ruby Random RNG, which is seeded with 42 - the answer to Life, Universe and
    Everything. You can verify that it is indeed so by generating the bytes yourself:
      Random.new(42).bytes(prime_used_to_size_file - preamble_byte_length)
    And now, enjoy randomness!
    =====================================================================
  ERR

  SCHEME_NAMES = [
    "BlockCipherKit::AES256CFBScheme",
    "BlockCipherKit::AES256CFBCIVScheme",
    "BlockCipherKit::AES256CTRScheme",
    "BlockCipherKit::AES256GCMScheme",
    "BlockCipherKit::AES256CBCScheme"
  ]
  SCHEME_NAMES_INCLUDING_PASSTHRU = SCHEME_NAMES + ["BlockCipherKit::PassthruScheme"]

  SCHEME_NAMES_INCLUDING_PASSTHRU.each do |scheme_class_name|
    define_method "test_scheme #{scheme_class_name} produces deterministic ciphertext" do
      assert_stable_ciphertext(scheme_class_name)
    end
  end

  def io_with_known_plaintext
    StringIO.new.binmode.tap do |out|
      # Generate a prime number of bytes, so that the plaintext does not
      # subdivide into blocks. This will allow us to find situations where
      # block offsets are not used for reading. To get this number, we used
      # OpenSSL::BN.generate_prime(12).to_i
      amount_of_plain_bytes = 3623
      n_bytes_of_randomness = amount_of_plain_bytes - PREAMBLE.bytesize
      out.write(PREAMBLE)
      out.write(Random.new(42).bytes(n_bytes_of_randomness))
      out.rewind
    end
  end

  def assert_stable_ciphertext(scheme_class_name)
    key = Random.new(21).bytes(64) # The scheme will use as many as it needs
    iv_rng = Random.new(42) # Ensure the cipher generates a deterministic IV, so that ciphertext comes out the same
    scheme = resolve(scheme_class_name).new(key, iv_generator: iv_rng)

    out = StringIO.new.binmode
    known_plaintext_path = __dir__ + "/known_ciphertexts/known_plain.bin"
    File.open(known_plaintext_path, "rb") do |f|
      scheme.streaming_encrypt(from_plaintext_io: f, into_ciphertext_io: out)
    end
    out.rewind

    known_ciphertext_path = __dir__ + "/known_ciphertexts/" + scheme.class.to_s.split("::").last + ".ciphertext.bin"
    File.open(known_ciphertext_path, "rb") do |f|
      assert_equal f.size, out.size, "The output of the scheme must be the same size as the known ciphertext"
      while (chunk = f.read(1024))
        assert_equal chunk, out.read(1024)
      end
    end
  end

  def regenerate_reference_files!
    key = Random.new(21).bytes(64) # The scheme will use as many as it needs
    iv_rng = Random.new(42) # Ensure the cipher generates a deterministic IV, so that ciphertext comes out the same
    scheme = resolve(scheme_class_name).new(key, iv_generator: iv_rng)

    known_plaintext_path = __dir__ + "/known_ciphertexts/known_plain.bin"
    File.open(known_plaintext_path, "wb") do |f|
      IO.copy_stream(io_with_known_plaintext, f)
    end

    known_ciphertext_path = __dir__ + "/known_ciphertexts/" + scheme.class.to_s.split("::").last + ".ciphertext.bin"
    File.open(known_ciphertext_path, "wb") do |f|
      scheme.streaming_encrypt(from_plaintext_io: io_with_known_plaintext, into_ciphertext_io: f)
    end
  end

  def resolve(module_name)
    module_name.split("::").reduce(Kernel) do |namespace, const_name|
      namespace.const_get(const_name)
    end
  end
end
