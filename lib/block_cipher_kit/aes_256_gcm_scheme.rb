class BlockCipherKit::AES256GCMScheme < BlockCipherKit::BaseScheme
  IV_LENGTH = 12

  def initialize(encryption_key, iv_generator: SecureRandom, auth_data: "")
    raise ArgumentError, "#{required_encryption_key_length} bytes of key material needed, at the minimum" unless encryption_key.bytesize >= required_encryption_key_length
    @iv_generator = iv_generator
    @auth_data = BlockCipherKit::KeyMaterial.new(auth_data.b)
    @key = BlockCipherKit::KeyMaterial.new(encryption_key.byteslice(0, 32))
  end

  def required_encryption_key_length
    32
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    iv = @iv_generator.bytes(IV_LENGTH)
    into_ciphertext_io.write(iv)

    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.iv = iv
    cipher.key = @key
    cipher.auth_data = @auth_data

    write_copy_stream_via_cipher(source_io: from_plaintext_io, cipher: cipher, destination_io: into_ciphertext_io, &blk)

    tag = cipher.auth_tag
    into_ciphertext_io.write(tag)
  end

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    # Read the IV
    iv = from_ciphertext_io.read(IV_LENGTH)
    start_at = from_ciphertext_io.pos

    # Read the auth tag, which we store after the ciphertext. This is streaming
    # decrypt, but we still assume random access is available for from_ciphertext_io.
    # We can access the ciphertext without tag validation but then it would be the same
    # "downgrade" to CTR as in decrypt_range.
    tag_len = 16
    from_ciphertext_io.seek(from_ciphertext_io.size - tag_len)
    auth_tag_from_io_tail = from_ciphertext_io.read(tag_len)

    # From the docs:
    # When decrypting, the authenticated data must be set after key, iv and especially
    # after the authentication tag has been set. I.e. set it only after calling #decrypt,
    # key=, #iv= and #auth_tag= first.
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.decrypt
    cipher.iv = iv
    cipher.key = @key
    cipher.auth_tag = auth_tag_from_io_tail
    cipher.auth_data = @auth_data

    from_ciphertext_io.seek(start_at)

    # We need to be careful not to read our auth tag along with the blocks,
    # because we appended it to the ciphertext ourselves - if the cipher considers
    # it part of ciphertext the validation will fail
    n_bytes_to_read_excluding_auth_tag = from_ciphertext_io.size - from_ciphertext_io.pos - tag_len

    # read_copy_stream_via_cipher will also call .final performing the validation
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, cipher: cipher, read_limit: n_bytes_to_read_excluding_auth_tag, destination_io: into_plaintext_io, &blk)
  end

  def decrypt_range(from_ciphertext_io:, range:)
    # GCM uses 16 byte blocks, but it writes the block
    # and the tag of 16 bytes. So actual block boundaries
    # are at 2x AES block size of 16 bytes. This is also
    # why the counter in the IV gets wound by 2 every time
    # we move from block to block.
    block_and_tag_size = 16 + 16

    n_blocks_to_skip, offset_into_first_block = range.begin.divmod(block_and_tag_size)
    n_bytes_to_read = range.end - range.begin + 1
    n_blocks_to_read = ((offset_into_first_block + n_bytes_to_read) / block_and_tag_size.to_f).ceil

    initial_iv_from_input = from_ciphertext_io.read(12)
    ciphertext_starts_at = from_ciphertext_io.pos

    # This is not a typo: we use GCM for encrypting the entire file and for decrypting the entire file, but to
    # have access to random blocks we need to downgrade to CTR, since we can't validate the tag anyway
    # This is a widely known trick, see
    # https://stackoverflow.com/questions/49228671/aes-gcm-decryption-bypassing-authentication-in-java/49244840#49244840
    # What we are doing here is not very secure
    # because we lose the authencation of the cipher (this does not verify the tag). But we can't actually
    # verify the tag without having decrypted the entire message.
    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    cipher.decrypt
    cipher.iv = ctr_iv(initial_iv_from_input, n_blocks_to_skip) # Set the IV for the first block we will be reading
    cipher.key = @key

    buf = StringIO.new.binmode
    from_ciphertext_io.seek(ciphertext_starts_at + (n_blocks_to_skip * block_and_tag_size))
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, cipher: cipher, read_limit: n_blocks_to_read * block_and_tag_size, destination_io: buf)
    buf.seek(offset_into_first_block) # Discard the bytes beyound the offset
    buf.read(n_bytes_to_read) # return just the amount of bytes requested
  end

  def ctr_iv(initial_iv_from_input, for_block_n)
    raise ArgumentError unless initial_iv_from_input.bytesize == 12
    # The counter gets incremented twice per block with GCM and the
    # initial counter value is 2 (as if there was a block before), see
    # https://stackoverflow.com/a/49244840
    ctr = (2 + (for_block_n * 2))
    initial_iv_from_input.b + [ctr].pack("N")
  end
end
