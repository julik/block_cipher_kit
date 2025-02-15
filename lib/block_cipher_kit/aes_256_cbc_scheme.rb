class BlockCipherKit::AES256CBCScheme < BlockCipherKit::BaseScheme
  def initialize(encryption_key)
    raise ArgumentError, "#{required_encryption_key_length} bytes of key material needed, at the minimum" unless encryption_key.bytesize >= required_encryption_key_length
    @iv = BlockCipherKit::KeyMaterial.new(encryption_key.byteslice(0, 16))
    @key = BlockCipherKit::KeyMaterial.new(encryption_key.byteslice(16, 32))
  end

  def required_encryption_key_length
    48
  end

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.decrypt
    cipher.iv = @iv
    cipher.key = @key
    read_copy_stream_via_cipher(source_io: from_ciphertext_io, cipher: cipher, destination_io: into_plaintext_io, &blk)
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.encrypt
    cipher.iv = @iv
    cipher.key = @key
    write_copy_stream_via_cipher(source_io: from_plaintext_io, cipher: cipher, destination_io: into_ciphertext_io, &blk)
  end

  def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk)
    block_size = 16

    n_bytes_to_decrypt = range.end - range.begin + 1
    n_blocks_to_skip, offset_into_first_block = range.begin.divmod(block_size)

    # If the from_io also contains some kind of header, we assume
    # that the pointer has been moved to where ciphertext begins - i.e.
    # using IO#seek. We need that pointer position so that we can
    # seek to block offsets correctly - otherwise we need a wrapper
    # which recomputes offsets in the IO
    ciphertext_starts_at = from_ciphertext_io.pos

    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.decrypt
    cipher.key = @key

    # If the first block we will be reading is going to be block 0
    # we can use our IV as-is
    if n_blocks_to_skip.zero?
      cipher.iv = @iv
    else
      # If we will be skipping blocks, we need the last skipped block
      # as it gets used as the IV for the first block we will actually decrypt.
      offset_of_preceding_block = (n_blocks_to_skip - 1) * block_size
      from_ciphertext_io.seek(ciphertext_starts_at + offset_of_preceding_block)
      cipher.iv = from_ciphertext_io.read(block_size)
    end

    # We need to read the blocks until the IO runs out, and we need to start reading at a block boundary
    from_ciphertext_io.seek(ciphertext_starts_at + (block_size * n_blocks_to_skip))

    writable = BlockCipherKit::BlockWritable.new(into_plaintext_io, &blk)
    lens_range = offset_into_first_block...(offset_into_first_block + n_bytes_to_decrypt)
    lens = BlockCipherKit::IOLens.new(writable, lens_range)

    read_copy_stream_via_cipher(source_io: from_ciphertext_io, destination_io: lens, cipher: cipher, finalize_cipher: true, read_limit: from_ciphertext_io.size - ciphertext_starts_at)
  end
end
