class BlockCipherKit::AES256CTRScheme < BlockCipherKit::BaseScheme
  NONCE_LENGTH_BYTES = 4
  IV_LENGTH_BYTES = 8

  # @param encryption_key[String] a String in binary encoding containing the key for the cipher
  # @param iv_generator[Random,SecureRandom] RNG that can output bytes. A deterministic substitute can be used for testing.
  def initialize(encryption_key, iv_generator: SecureRandom)
    raise ArgumentError, "#{required_encryption_key_length} bytes of key material needed, at the minimum" unless encryption_key.bytesize >= required_encryption_key_length
    @iv_generator = iv_generator
    @key = encryption_key.byteslice(0, 32)
  end

  def required_encryption_key_length
    32
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    nonce_and_iv = @iv_generator.bytes(NONCE_LENGTH_BYTES + IV_LENGTH_BYTES)
    into_ciphertext_io.write(nonce_and_iv)

    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    cipher.encrypt
    cipher.iv = ctr_iv(nonce_and_iv, _for_block_n = 0)
    cipher.key = @key
    write_copy_stream_via_cipher(source_io: from_plaintext_io, cipher: cipher, destination_io: into_ciphertext_io, &blk)
  end

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    nonce_and_iv = from_ciphertext_io.read(NONCE_LENGTH_BYTES + IV_LENGTH_BYTES)

    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    cipher.decrypt
    cipher.iv = ctr_iv(nonce_and_iv, _for_block_n = 0)
    cipher.key = @key
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, cipher: cipher, destination_io: into_plaintext_io, &blk)
  end

  def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk)
    block_size = 16
    n_bytes_to_read = range.end - range.begin + 1
    n_blocks_to_skip, offset_into_first_block = range.begin.divmod(block_size)

    nonce_and_iv = from_ciphertext_io.read(NONCE_LENGTH_BYTES + IV_LENGTH_BYTES)
    ciphertext_starts_at = from_ciphertext_io.pos

    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    cipher.decrypt
    cipher.key = @key
    cipher.iv = ctr_iv(nonce_and_iv, n_blocks_to_skip) # Set the counter for the first block we will be reading

    writable = BlockCipherKit::BlockWritable.new(into_plaintext_io, &blk)
    lens = BlockCipherKit::WriteWindowIO.new(writable, offset_into_first_block, n_bytes_to_read)

    # With CTR we do not need to read until the end of ciphertext as the cipher does not validate
    from_ciphertext_io.seek(ciphertext_starts_at + (n_blocks_to_skip * block_size))
    n_blocks_to_read = (n_bytes_to_read.to_f / block_size).ceil + 1
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, destination_io: lens, cipher: cipher, read_limit: n_blocks_to_read * block_size)
  end

  private

  def ctr_iv(nonce_and_iv, for_block_n)
    # The IV is the counter block
    # see spec https://datatracker.ietf.org/doc/html/rfc3686#section-4
    # It consists of:
    # * a nonce (which should be the same across all blocks) - 4 bytes,
    # * a chunk of the initial IV bytes - this is used as the actual IV - 8 bytes
    # * and the counter, encoded as a big endian uint - 4 bytes
    #
    # So, while the OpenSSL Cipher reports iv_len to be 16 bytes, it is lying -
    # even if it uses the IV to split it into a nonce + iv part, 4 bytes will be...zeroed?
    # ignored? something else?
    # Either way: for the nonce we can consume a part of our initial IV, for the block IV
    # we can consume the rest of the initial IV, and the last 4 bytes will be the counter.
    # The rest of the state will be maintained by the Cipher, luckily.
    # nonce = iv_initial.byteslice(0, 4)
    # iv_part = iv_initial.byteslice(3, 8)
    #
    # Also... the counter resets once we got more than 0xFFFFFFFF blocks?
    # It seems in its infinite wisdom the library we are using (whichever) will do
    # whatever the system integer overflow does?..
    # https://stackoverflow.com/questions/66790768/aes256-ctr-mode-behavior-on-counter-overflow-rollover
    # https://crypto.stackexchange.com/a/71210
    # https://crypto.stackexchange.com/a/71196
    # But for the counter to overflow we would need our input to be more than 68719476720 bytes.
    # That is just short of 64 gigabytes (!). Maybe we need a backstop for that. Or maybe we don't.
    raise ArgumentError unless nonce_and_iv.bytesize == 12
    nonce_and_iv.b + [for_block_n + 1].pack("N")
  end
end
