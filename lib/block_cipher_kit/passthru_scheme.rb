class BlockCipherKit::PassthruScheme < BlockCipherKit::BaseScheme
  def initialize(...)
  end

  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    w = into_plaintext_io || BlockCipherKit::BlockWritable.new(&blk)
    IO.copy_stream(from_ciphertext_io, w)
  end

  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    if from_plaintext_io && !blk
      IO.copy_stream(from_plaintext_io, into_ciphertext_io)
    elsif blk
      blk.call(into_ciphertext_io)
    else
      raise ArgumentError
    end
  end

  def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk)
    from_ciphertext_io.seek(from_ciphertext_io.pos + range.begin)
    n_bytes = range.end - range.begin + 1
    w = BlockCipherKit::BlockWritable.new(into_plaintext_io, &blk)
    w.write(from_ciphertext_io.read(n_bytes))
  end
end
