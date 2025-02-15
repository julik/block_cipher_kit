class BlockCipherKit::AES256CFBScheme < BlockCipherKit::BaseScheme
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
    cipher = OpenSSL::Cipher.new("aes-256-cfb")
    cipher.decrypt
    cipher.iv = from_ciphertext_io.read(IV_LENGTH)
    cipher.key = @key
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, cipher: cipher, destination_io: into_plaintext_io, &blk)
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    iv = @iv_generator.bytes(16)
    cipher = OpenSSL::Cipher.new("aes-256-cfb")
    cipher.encrypt
    cipher.iv = iv
    cipher.key = @key
    into_ciphertext_io.write(iv)
    write_copy_stream_via_cipher(source_io: from_plaintext_io, cipher: cipher, destination_io: into_ciphertext_io, &blk)
  end

  def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk)
    # There is potential, but I don't have time for this at the moment
    # https://crypto.stackexchange.com/a/87007
    writable = BlockCipherKit::BlockWritable.new(into_plaintext_io, &blk)
    lens = BlockCipherKit::IOLens.new(writable, range)
    streaming_decrypt(from_ciphertext_io: from_ciphertext_io, into_plaintext_io: lens)
  end
end
