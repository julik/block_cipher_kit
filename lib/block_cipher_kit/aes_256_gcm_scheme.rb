class BlockCipherKit::AES256GCMScheme < BlockCipherKit::BaseScheme
  def initialize(encryption_key)
    raise ArgumentError, "#{required_encryption_key_length} bytes of key material needed, at the minimum" unless encryption_key.bytesize >= required_encryption_key_length
    @iv = BlockCipherKit::KeyMaterial.new(encryption_key.byteslice(0, 12))
    @key = BlockCipherKit::KeyMaterial.new(encryption_key.byteslice(12, 32))
  end

  def required_encryption_key_length
    44
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.iv = @iv
    cipher.key = @key
    cipher.auth_data = ""
    write_copy_stream_via_cipher(source_io: from_plaintext_io, cipher: cipher, destination_io: into_ciphertext_io, &blk)
    tag = cipher.auth_tag
    into_ciphertext_io.write(tag)
  end

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
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
    cipher.iv = @iv
    cipher.key = @key
    cipher.auth_tag = auth_tag_from_io_tail
    cipher.auth_data = ""

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

    # If the from_io also contains some kind of header, we assume
    # that the pointer has been moved to where ciphertext begins - i.e.
    # using IO#seek. We need that pointer position so that we can
    # seek to block offsets correctly - otherwise we need a wrapper
    # which recomputes offsets in the IO
    ciphertext_starts_at = from_ciphertext_io.pos

    # Use the CTR cipher mode so that we can use counters easily, see
    # https://stackoverflow.com/questions/49228671/aes-gcm-decryption-bypassing-authentication-in-java/49244840#49244840
    # What we are doing here is not very secure
    # because we lose the authencation of the cipher (this does not verify the tag). But we can't actually
    # verify the tag without having decrypted the entire file (the entire message).
    #
    # So this is not a typo: we use GCM for encrypting the entire file and for decrypting the entire file, but to
    # have access to random blocks we need to downgrade to CTR, since we can't validate the tag anyway
    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    cipher.decrypt
    cipher.iv = ctr_iv(n_blocks_to_skip) # Set the IV for the first block we will be reading
    cipher.key = @key

    buf = StringIO.new.binmode
    from_ciphertext_io.seek(ciphertext_starts_at + (n_blocks_to_skip * block_and_tag_size))
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, cipher: cipher, read_limit: n_blocks_to_read * block_and_tag_size, destination_io: buf)
    buf.seek(offset_into_first_block) # Discard the bytes beyound the offset
    buf.read(n_bytes_to_read) # return just the amount of bytes requested
  end

  def ctr_iv(for_block_n)
    # The counter gets incremented twice per block with GCM and the
    # initial counter value is 2 (as if there was a block before), see
    # https://stackoverflow.com/a/49244840
    ctr = (2 + (for_block_n * 2))
    @iv.b + [ctr].pack("N")
  end
end
