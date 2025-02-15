class BlockCipherKit::BaseScheme
  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    raise "Unimplemented"
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    raise "Unimplemented"
  end

  def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk)
    raise "Unimplemented"
  end

  def decrypt_range(from_ciphertext_io:, range:)
    buf = StringIO.new.binmode
    streaming_decrypt_range(from_ciphertext_io: from_ciphertext_io, range: range, into_plaintext_io: buf)
    buf.string
  end

  def read_copy_stream_via_cipher(source_io:, cipher:, read_limit: nil, destination_io: nil, finalize_cipher: true, &block_accepting_byte_chunks)
    writable = BlockCipherKit::BlockWritable.new(destination_io, &block_accepting_byte_chunks)
    cipher_io = BlockCipherKit::CipherIO.new(writable, cipher)
    IO.copy_stream(source_io, cipher_io, read_limit)
    # Some cases require us to skip authentication which gets performed in cipher.final
    # - like decrypting a few blocks of CBC without decrypting the last block. This skips cipher
    # authentication but is required for random access.
    writable.write(cipher.final) if finalize_cipher
  end

  def write_copy_stream_via_cipher(cipher:, destination_io:, source_io: nil, read_limit: nil, &block_accepting_writable_io)
    w = BlockCipherKit::CipherIO.new(destination_io, cipher)
    if !source_io && block_accepting_writable_io && !read_limit
      block_accepting_writable_io.call(w)
    elsif !source_io && block_accepting_writable_io && read_limit
      raise "write_copy_stream_via_cipher cannot enforce read_limit when writing via a block"
    elsif source_io && !block_accepting_writable_io
      IO.copy_stream(source_io, w, read_limit)
    else
      raise ArgumentError, "Either source_io: or a block accepting a writable IO must be provided"
    end
    destination_io.write(cipher.final)
  end
end
