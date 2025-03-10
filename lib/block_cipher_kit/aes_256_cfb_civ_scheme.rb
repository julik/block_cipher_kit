require "tempfile"

class BlockCipherKit::AES256CFBCIVScheme < BlockCipherKit::BaseScheme
  # @param encryption_key[String] a String in binary encoding containing the IV concatenated with the key for the cipher
  def initialize(encryption_key, **)
    raise ArgumentError, "#{required_encryption_key_length} bytes of key material needed, at the minimum" unless encryption_key.bytesize >= required_encryption_key_length
    @iv = encryption_key.byteslice(0, 16)
    @key = encryption_key.byteslice(16, 32)
  end

  def required_encryption_key_length
    48
  end

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    cipher = OpenSSL::Cipher.new("aes-256-cfb")
    cipher.decrypt
    cipher.iv = @iv
    cipher.key = @key
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, cipher: cipher, destination_io: into_plaintext_io, &blk)
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    cipher = OpenSSL::Cipher.new("aes-256-cfb")
    cipher.encrypt
    cipher.iv = @iv
    cipher.key = @key
    write_copy_stream_via_cipher(source_io: from_plaintext_io, cipher: cipher, destination_io: into_ciphertext_io, &blk)
  end

  def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk)
    writable = BlockCipherKit::BlockWritable.new(into_plaintext_io, &blk)
    lens = BlockCipherKit::WriteWindowIO.new(writable, range.begin, range.end - range.begin + 1)
    streaming_decrypt(from_ciphertext_io: from_ciphertext_io, into_plaintext_io: lens)
  end
end
