# typed: strong
module BlockCipherKit
  VERSION = T.let("0.0.1", T.untyped)

  # Allows you to pass through the writes of a particular byte range only, discarding the rest
  class IOLens
    # sord omit - no YARD type given for "io", using untyped
    # sord omit - no YARD type given for "range", using untyped
    sig { params(io: T.untyped, range: T.untyped).void }
    def initialize(io, range); end

    # sord omit - no YARD type given for "bytes", using untyped
    # sord omit - no YARD return type given, using untyped
    sig { params(bytes: T.untyped).returns(T.untyped) }
    def write(bytes); end

    # sord omit - no YARD type given for "range_a", using untyped
    # sord omit - no YARD type given for "range_b", using untyped
    # sord omit - no YARD return type given, using untyped
    # lifted from https://github.com/julik/range_utils/blob/master/lib/range_utils.rb
    sig { params(range_a: T.untyped, range_b: T.untyped).returns(T.untyped) }
    def intersection_of(range_a, range_b); end
  end

  # Allows an OpenSSL::Cipher to be written through as if it were an IO. This
  # allows the cipher to be passed to things like IO.copy_stream
  class CipherIO
    # sord omit - no YARD type given for "io", using untyped
    # sord omit - no YARD type given for "cipher", using untyped
    sig { params(io: T.untyped, cipher: T.untyped).void }
    def initialize(io, cipher); end

    # sord omit - no YARD type given for "bytes", using untyped
    # sord omit - no YARD return type given, using untyped
    sig { params(bytes: T.untyped).returns(T.untyped) }
    def write(bytes); end
  end

  class BaseScheme
    # Decrypts the entire ciphered message, reading ciphertext out of `from_ciphertext_io`
    # until its `read` returns `nil` (until EOF is implicitly reached). The scheme
    # will also read any data at the start of the IO that it requires for
    # operation, and consume the IO until exhaustion.
    # 
    # _@param_ `from_ciphertext_io` — An IO-ish that responds to `read` with one argument, ciphertext will be read from that IO
    # 
    # _@param_ `into_plaintext_io` — An IO-ish that responds to `write` with one argument. If into_plaintext_io is not provided, the block passed to the method will receive String objects in binary encoding with chunks of decrypted ciphertext. The sizing of the chunks is defined by the cipher and the read size used by `IO.copy_stream`
    sig { params(from_ciphertext_io: StraightReadableIO, into_plaintext_io: T.nilable(WritableIO), blk: T.untyped).void }
    def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk); end

    # Encrypts the entire ciphered message, reading plaintext either from the `from_plaintext_io`
    # until its `read` returns `nil` (until EOF is implicitly reached) or from writes to
    # the object it yields (for streaming writes).
    # 
    # The scheme will also write any leading data at the start of the output that should prefix the
    # ciphertext (usually the IV) and any trailing data after the ciphertext (like a validation
    # tag for cipher authentication) into the `into_ciphertext_io`.
    # 
    # _@param_ `from_plaintext_io` — An IO-ish that responds to `read` with one argument. If from_plaintext_io is not provided, the block passed to the method will receive an IO-ish object that responds to `#write` that plaintext can be written into.
    # 
    # _@param_ `into_ciphertext_io` — An IO-ish that responds to `write` with one argument,
    sig { params(into_ciphertext_io: WritableIO, from_plaintext_io: T.nilable(StraightReadableIO), blk: T.untyped).void }
    def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk); end

    # Decrypts the desired range of the ciphered message, reading ciphertext out of `from_ciphertext_io`.
    # Reading requires the `from_ciphertext_io` to be seekable - it must support `#pos`, `#read`and `#seek`.
    # The decrypted plaintext either gets written into `into_plaintext_io` if it is provided, or yielded
    # to the passed block in String chunks.
    # 
    # _@param_ `from_ciphertext_io` — Ciphertext will be read from that IO. The IO must support random access.
    # 
    # _@param_ `range` — range of bytes in plaintext offsets to decrypt. Endless ranges are supported.
    # 
    # _@param_ `into_plaintext_io` — An IO-ish that responds to `write` with one argument. If into_plaintext_io is not provided, the block passed to the method will receive String objects in binary encoding with chunks of decrypted ciphertext. The sizing of the chunks is defined by the cipher and the read size used by `IO.copy_stream`
    sig do
      params(
        from_ciphertext_io: RandomReadIO,
        range: T::Range[T.untyped],
        into_plaintext_io: T.nilable(WritableIO),
        blk: T.untyped
      ).void
    end
    def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk); end

    # Decrypts the desired range of the ciphered message, reading ciphertext out of `from_ciphertext_io`.
    # Reading requires the `from_ciphertext_io` to be seekable - it must support `#pos`, `#read`and `#seek`.
    # The decrypted plaintext gets returned as a single concatenated String.
    # 
    # _@param_ `from_ciphertext_io` — Ciphertext will be read from that IO. The IO must support random access.
    # 
    # _@param_ `range` — range of bytes in plaintext offsets to decrypt. Endless ranges are supported.
    # 
    # _@return_ — the decrypted bytes located at the given offset range inside the plaintext
    sig { params(from_ciphertext_io: RandomReadIO, range: T::Range[T.untyped]).returns(String) }
    def decrypt_range(from_ciphertext_io:, range:); end

    # sord omit - no YARD type given for "source_io:", using untyped
    # sord omit - no YARD type given for "cipher:", using untyped
    # sord omit - no YARD type given for "read_limit:", using untyped
    # sord omit - no YARD type given for "destination_io:", using untyped
    # sord omit - no YARD type given for "finalize_cipher:", using untyped
    # sord omit - no YARD return type given, using untyped
    sig do
      params(
        source_io: T.untyped,
        cipher: T.untyped,
        read_limit: T.untyped,
        destination_io: T.untyped,
        finalize_cipher: T.untyped,
        block_accepting_byte_chunks: T.untyped
      ).returns(T.untyped)
    end
    def read_copy_stream_via_cipher(source_io:, cipher:, read_limit: nil, destination_io: nil, finalize_cipher: true, &block_accepting_byte_chunks); end

    # sord omit - no YARD type given for "cipher:", using untyped
    # sord omit - no YARD type given for "destination_io:", using untyped
    # sord omit - no YARD type given for "source_io:", using untyped
    # sord omit - no YARD type given for "read_limit:", using untyped
    # sord omit - no YARD return type given, using untyped
    sig do
      params(
        cipher: T.untyped,
        destination_io: T.untyped,
        source_io: T.untyped,
        read_limit: T.untyped,
        block_accepting_writable_io: T.untyped
      ).returns(T.untyped)
    end
    def write_copy_stream_via_cipher(cipher:, destination_io:, source_io: nil, read_limit: nil, &block_accepting_writable_io); end
  end

  # Allows a string with key material (like IV and key)
  # to be concealed when an object holding it gets printed or show via #inspect
  class KeyMaterial
    extend Forwardable

    # sord omit - no YARD type given for "str", using untyped
    sig { params(str: T.untyped).void }
    def initialize(str); end

    # sord omit - no YARD return type given, using untyped
    sig { returns(T.untyped) }
    def inspect; end
  end

  # An adapter which allows a block that accepts chunks of
  # written data to be used as an IO and passed to IO.copy_stream
  class BlockWritable
    # sord omit - no YARD type given for "io", using untyped
    # sord omit - no YARD return type given, using untyped
    sig { params(io: T.untyped, blk: T.untyped).returns(T.untyped) }
    def self.new(io = nil, &blk); end

    sig { params(blk: T.untyped).void }
    def initialize(&blk); end

    # sord omit - no YARD type given for "string", using untyped
    # sord omit - no YARD return type given, using untyped
    sig { params(string: T.untyped).returns(T.untyped) }
    def write(string); end
  end

  class PassthruScheme < BlockCipherKit::BaseScheme
    sig { void }
    def initialize; end

    sig { params(from_ciphertext_io: StraightReadableIO, into_plaintext_io: T.nilable(WritableIO), blk: T.untyped).void }
    def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk); end

    sig { params(into_ciphertext_io: WritableIO, from_plaintext_io: T.nilable(StraightReadableIO), blk: T.untyped).void }
    def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk); end

    sig do
      params(
        from_ciphertext_io: RandomReadIO,
        range: T::Range[T.untyped],
        into_plaintext_io: T.nilable(WritableIO),
        blk: T.untyped
      ).void
    end
    def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk); end
  end

  class AES256CBCScheme < BlockCipherKit::BaseScheme
    IV_LENGTH = T.let(16, T.untyped)

    # sord duck - #bytes looks like a duck type, replacing with untyped
    # _@param_ `encryption_key` — a String in binary encoding containing the key for the cipher
    # 
    # _@param_ `iv_generator` — RNG that can output bytes. A deterministic substitute can be used for testing.
    sig { params(encryption_key: String, iv_generator: T.untyped).void }
    def initialize(encryption_key, iv_generator: SecureRandom); end

    # sord omit - no YARD return type given, using untyped
    sig { returns(T.untyped) }
    def required_encryption_key_length; end

    sig { params(from_ciphertext_io: StraightReadableIO, into_plaintext_io: T.nilable(WritableIO), blk: T.untyped).void }
    def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk); end

    sig { params(into_ciphertext_io: WritableIO, from_plaintext_io: T.nilable(StraightReadableIO), blk: T.untyped).void }
    def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk); end

    sig do
      params(
        from_ciphertext_io: RandomReadIO,
        range: T::Range[T.untyped],
        into_plaintext_io: T.nilable(WritableIO),
        blk: T.untyped
      ).void
    end
    def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk); end
  end

  class AES256CFBScheme < BlockCipherKit::BaseScheme
    IV_LENGTH = T.let(16, T.untyped)

    # sord omit - no YARD type given for "encryption_key", using untyped
    # sord omit - no YARD type given for "iv_generator:", using untyped
    sig { params(encryption_key: T.untyped, iv_generator: T.untyped).void }
    def initialize(encryption_key, iv_generator: SecureRandom); end

    # sord omit - no YARD return type given, using untyped
    sig { returns(T.untyped) }
    def required_encryption_key_length; end

    sig { params(from_ciphertext_io: StraightReadableIO, into_plaintext_io: T.nilable(WritableIO), blk: T.untyped).void }
    def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk); end

    sig { params(into_ciphertext_io: WritableIO, from_plaintext_io: T.nilable(StraightReadableIO), blk: T.untyped).void }
    def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk); end

    sig do
      params(
        from_ciphertext_io: RandomReadIO,
        range: T::Range[T.untyped],
        into_plaintext_io: T.nilable(WritableIO),
        blk: T.untyped
      ).void
    end
    def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk); end
  end

  class AES256CTRScheme < BlockCipherKit::BaseScheme
    NONCE_LENGTH_BYTES = T.let(4, T.untyped)
    IV_LENGTH_BYTES = T.let(8, T.untyped)

    # sord duck - #bytes looks like a duck type, replacing with untyped
    # _@param_ `encryption_key` — a String in binary encoding containing the key for the cipher
    # 
    # _@param_ `iv_generator` — RNG that can output bytes. A deterministic substitute can be used for testing.
    sig { params(encryption_key: String, iv_generator: T.untyped).void }
    def initialize(encryption_key, iv_generator: SecureRandom); end

    # sord omit - no YARD return type given, using untyped
    sig { returns(T.untyped) }
    def required_encryption_key_length; end

    sig { params(into_ciphertext_io: WritableIO, from_plaintext_io: T.nilable(StraightReadableIO), blk: T.untyped).void }
    def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk); end

    sig { params(from_ciphertext_io: StraightReadableIO, into_plaintext_io: T.nilable(WritableIO), blk: T.untyped).void }
    def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk); end

    sig do
      params(
        from_ciphertext_io: RandomReadIO,
        range: T::Range[T.untyped],
        into_plaintext_io: T.nilable(WritableIO),
        blk: T.untyped
      ).void
    end
    def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk); end

    # sord omit - no YARD type given for "nonce_and_iv", using untyped
    # sord omit - no YARD type given for "for_block_n", using untyped
    # sord omit - no YARD return type given, using untyped
    sig { params(nonce_and_iv: T.untyped, for_block_n: T.untyped).returns(T.untyped) }
    def ctr_iv(nonce_and_iv, for_block_n); end
  end

  class AES256GCMScheme < BlockCipherKit::BaseScheme
    IV_LENGTH = T.let(12, T.untyped)

    # sord duck - #bytes looks like a duck type, replacing with untyped
    # _@param_ `encryption_key` — a String in binary encoding containing the key for the cipher
    # 
    # _@param_ `iv_generator` — RNG that can output bytes. A deterministic substitute can be used for testing.
    # 
    # _@param_ `auth_data` — optional auth data for the cipher. If provided, this auth data will be used to write ciphertext and to validate.
    sig { params(encryption_key: String, iv_generator: T.untyped, auth_data: String).void }
    def initialize(encryption_key, iv_generator: SecureRandom, auth_data: ""); end

    # sord omit - no YARD return type given, using untyped
    sig { returns(T.untyped) }
    def required_encryption_key_length; end

    sig { params(into_ciphertext_io: WritableIO, from_plaintext_io: T.nilable(StraightReadableIO), blk: T.untyped).void }
    def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk); end

    sig { params(from_ciphertext_io: StraightReadableIO, into_plaintext_io: T.nilable(WritableIO), blk: T.untyped).void }
    def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk); end

    # Range decryption with GCM is performed by downgrading the GCM cipher to a CTR cipher, validation
    # gets skipped.
    # 
    # _@see_ `BaseScheme#streaming_decrypt_range`
    sig do
      params(
        from_ciphertext_io: RandomReadIO,
        range: T::Range[T.untyped],
        into_plaintext_io: T.nilable(WritableIO),
        blk: T.untyped
      ).void
    end
    def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk); end

    # sord omit - no YARD type given for "initial_iv_from_input", using untyped
    # sord omit - no YARD type given for "for_block_n", using untyped
    # sord omit - no YARD return type given, using untyped
    sig { params(initial_iv_from_input: T.untyped, for_block_n: T.untyped).returns(T.untyped) }
    def ctr_iv(initial_iv_from_input, for_block_n); end
  end

  class AES256CFBCIVScheme < BlockCipherKit::BaseScheme
    # _@param_ `encryption_key` — a String in binary encoding containing the IV concatenated with the key for the cipher
    sig { params(encryption_key: String).void }
    def initialize(encryption_key); end

    # sord omit - no YARD return type given, using untyped
    sig { returns(T.untyped) }
    def required_encryption_key_length; end

    sig { params(from_ciphertext_io: StraightReadableIO, into_plaintext_io: T.nilable(WritableIO), blk: T.untyped).void }
    def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk); end

    sig { params(into_ciphertext_io: WritableIO, from_plaintext_io: T.nilable(StraightReadableIO), blk: T.untyped).void }
    def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk); end

    sig do
      params(
        from_ciphertext_io: RandomReadIO,
        range: T::Range[T.untyped],
        into_plaintext_io: T.nilable(WritableIO),
        blk: T.untyped
      ).void
    end
    def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk); end
  end
end

# Used as a stand-in for any IO-ish that responds to #read
module StraightReadableIO
  # sord infer - argument name in single @param inferred as "n"
  # _@param_ `how` — many bytes to read from the IO
  # 
  # _@return_ — a String in binary encoding or nil
  sig { params(n: Integer).returns(T.nilable(String)) }
  def read(n); end
end

# Used as a stand-in for any IO-ish that responds to `#read`, `#seek`, `#pos` and `#size`
module RandomReadIO
  # sord infer - argument name in single @param inferred as "n"
  # _@param_ `how` — many bytes to read from the IO
  # 
  # _@return_ — a String in binary encoding or nil
  sig { params(n: Integer).returns(T.nilable(String)) }
  def read(n); end

  # sord infer - argument name in single @param inferred as "to_absolute_offset"
  # _@param_ `the` — absolute offset in the IO to seek to
  # 
  # _@return_ — 0
  sig { params(to_absolute_offset: Integer).returns(T.untyped) }
  def seek(to_absolute_offset); end

  # _@return_ — current position in the IO
  sig { returns(Integer) }
  def pos; end

  # _@return_ — the total size of the data in the IO
  sig { returns(Integer) }
  def size; end
end

module WritableIO
  # sord infer - argument name in single @param inferred as "n"
  # _@param_ `the` — bytes to write into the IO
  # 
  # _@return_ — the amount of bytes consumed. Will usually be `bytes.bytesize`
  sig { params(n: String).returns(Integer) }
  def write(n); end
end
