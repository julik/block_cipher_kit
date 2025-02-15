require "securerandom"

class BlockCipherKit::AES256CBCScheme < BlockCipherKit::BaseScheme
  IV_LENGTH = 16

  def initialize(encryption_key, iv_generator: SecureRandom)
    raise ArgumentError, "#{required_encryption_key_length} bytes of key material needed, at the minimum" unless encryption_key.bytesize >= required_encryption_key_length
    @iv_generator = iv_generator
    @key = BlockCipherKit::KeyMaterial.new(encryption_key.byteslice(0, 32))
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

    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.decrypt
    cipher.key = @key

    # We need to read the IV either from the start of the IO (the initial IV)
    # or from the block preceding the first block we need to decrypt
    from_ciphertext_io.seek(from_ciphertext_io.pos + (n_blocks_to_skip * block_size))
    cipher.iv = from_ciphertext_io.read(IV_LENGTH)

    writable = BlockCipherKit::BlockWritable.new(into_plaintext_io, &blk)
    lens_range = offset_into_first_block...(offset_into_first_block + n_bytes_to_decrypt)
    lens = BlockCipherKit::IOLens.new(writable, lens_range)

    # TODO: it seems that if we read only the blocks we touch, we need to call cipher.final to get all the output - the cipher buffers,
    # but if we call .final without having read the entire ciphertext the cipher will barf. This needs to be fixed as it is certainly possible with CBC.
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, destination_io: lens, cipher: cipher, finalize_cipher: true, read_limit: from_ciphertext_io.size - from_ciphertext_io.pos)
  end
end
