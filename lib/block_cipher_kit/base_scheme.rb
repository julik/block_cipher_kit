class BlockCipherKit::BaseScheme
  # Decrypts the entire ciphered message, reading ciphertext out of `from_ciphertext_io`
  # until its `read` returns `nil` (until EOF is implicitly reached). The scheme
  # will also read any data at the start of the IO that it requires for
  # operation, and consume the IO until exhaustion.
  #
  # @param from_ciphertext_io[StraightReadableIO] An IO-ish that responds to `read` with one argument,
  #     ciphertext will be read from that IO
  # @param into_plaintext_io[WritableIO] An IO-ish that responds to `write` with one argument.
  #     If into_plaintext_io is not provided, the block passed to the method will receive
  #     String objects in binary encoding with chunks of decrypted ciphertext. The sizing
  #     of the chunks is defined by the cipher and the read size used by `IO.copy_stream`
  # @yield [String] the chunk of decrypted bytes
  # @return [void]
  def streaming_decrypt(from_ciphertext_io:, into_plaintext_io: nil, &blk)
    raise "Unimplemented"
  end

  # Encrypts the entire ciphered message, reading plaintext either from the `from_plaintext_io`
  # until its `read` returns `nil` (until EOF is implicitly reached) or from writes to
  # the object it yields (for streaming writes).
  #
  # The scheme will also write any leading data at the start of the output that should prefix the
  # ciphertext (usually the IV) and any trailing data after the ciphertext (like a validation
  # tag for cipher authentication) into the `into_ciphertext_io`.
  #
  # @param from_plaintext_io[StraightReadableIO,nil] An IO-ish that responds to `read` with one argument.
  #     If from_plaintext_io is not provided, the block passed to the method will receive
  #     an IO-ish object that responds to `#write` that plaintext can be written into.
  # @param into_ciphertext_io[WritableIO] An IO-ish that responds to `write` with one argument,
  # @yield [#write] IO-ish writable that accepts strings of plaintext into `#write`
  # @return [void]
  def streaming_encrypt(into_ciphertext_io:, from_plaintext_io: nil, &blk)
    raise "Unimplemented"
  end

  # Decrypts the desired range of the ciphered message, reading ciphertext out of `from_ciphertext_io`.
  # Reading requires the `from_ciphertext_io` to be seekable - it must support `#pos`, `#read`and `#seek`.
  # The decrypted plaintext either gets written into `into_plaintext_io` if it is provided, or yielded
  # to the passed block in String chunks.
  #
  # @param from_ciphertext_io[RandomReadIO] Ciphertext will be read from that IO. The IO must support random access.
  # @param range[Range] range of bytes in plaintext offsets to decrypt. Endless ranges are supported.
  # @param into_plaintext_io[WritableIO] An IO-ish that responds to `write` with one argument.
  #     If into_plaintext_io is not provided, the block passed to the method will receive
  #     String objects in binary encoding with chunks of decrypted ciphertext. The sizing
  #     of the chunks is defined by the cipher and the read size used by `IO.copy_stream`
  # @yield [String] the chunk of decrypted bytes
  # @return [void]
  def streaming_decrypt_range(from_ciphertext_io:, range:, into_plaintext_io: nil, &blk)
    raise "Unimplemented"
  end

  # Decrypts the desired range of the ciphered message, reading ciphertext out of `from_ciphertext_io`.
  # Reading requires the `from_ciphertext_io` to be seekable - it must support `#pos`, `#read`and `#seek`.
  # The decrypted plaintext gets returned as a single concatenated String.
  #
  # @param from_ciphertext_io[RandomReadIO] Ciphertext will be read from that IO. The IO must support random access.
  # @param range[Range] range of bytes in plaintext offsets to decrypt. Endless ranges are supported.
  # @return [String] the decrypted bytes located at the given offset range inside the plaintext
  def decrypt_range(from_ciphertext_io:, range:)
    buf = StringIO.new.binmode
    streaming_decrypt_range(from_ciphertext_io: from_ciphertext_io, range: range, into_plaintext_io: buf)
    buf.string
  end

  def inspect
    # A reimplementation of #inspect based largely on
    # https://alchemists.io/articles/ruby_object_inspection
    pattern = +""
    values = []

    instance_variables.each do |name|
      pattern << "#{name}=%s "
      ivar_value = instance_variable_get(name)
      if ivar_value.is_a?(String) && key_material_instance_variable_names.include?(name)
        values.push("[SENSITIVE(#{ivar_value.bytesize * 8} bits)]")
      else
        values.push(ivar_value.inspect)
      end
    end

    format "#<%s:%#018x #{pattern.strip}>", self.class, object_id << 1, *values
  end

  private

  # The names of instance variables which contain key material and need to be masked in the
  # output of BaseScheme#inspect. This prevents us from leaking the key, while allowing each
  # subclass to define which ivars it considers sensitive.
  def key_material_instance_variable_names
    [:@key, :@iv]
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
