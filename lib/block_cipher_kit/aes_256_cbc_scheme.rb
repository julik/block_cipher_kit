require "securerandom"

class BlockCipherKit::AES256CBCScheme < BlockCipherKit::BaseScheme
  IV_LENGTH = 16

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

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.decrypt
    cipher.iv = from_ciphertext_io.read(IV_LENGTH)
    cipher.key = @key
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, cipher: cipher, destination_io: into_plaintext_io, &blk)
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    random_iv = @iv_generator.bytes(IV_LENGTH)
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.encrypt
    cipher.iv = random_iv
    cipher.key = @key
    into_ciphertext_io.write(random_iv)
    write_copy_stream_via_cipher(source_io: from_plaintext_io, cipher: cipher, destination_io: into_ciphertext_io, &blk)
  end

  def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk)
    block_size = 16
    n_bytes_to_decrypt = range.end - range.begin + 1
    n_blocks_to_skip, offset_into_first_block = range.begin.divmod(block_size)

    # We need to read ahead to know well whether to call "final" on the cipher
    n_blocks_to_read = (n_bytes_to_decrypt.to_f / block_size).ceil + 2
    n_bytes_to_read = (n_blocks_to_read * block_size)

    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.decrypt
    cipher.key = @key

    # We need to read the IV either from the start of the IO (the initial IV)
    # or from the block preceding the first block we need to decrypt
    from_ciphertext_io.seek(from_ciphertext_io.pos + (n_blocks_to_skip * block_size))
    cipher.iv = from_ciphertext_io.read(IV_LENGTH)

    writable = BlockCipherKit::BlockWritable.new(into_plaintext_io, &blk)
    lens = BlockCipherKit::WriteWindowIO.new(writable, offset_into_first_block, n_bytes_to_decrypt)

    # We need to know whether we are going to be finishing our read with a block that may be shorter than
    # block_size. In that case we must call `.final` on the cipher so that it releases us the decrypted
    # plaintext instead of waiting for the remainder of the bits the last block consists of
    bytes_remaining = from_ciphertext_io.size - from_ciphertext_io.pos
    do_finalize = bytes_remaining < n_bytes_to_read
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, destination_io: lens, cipher: cipher, finalize_cipher: do_finalize, read_limit: n_bytes_to_read)
  end
end
