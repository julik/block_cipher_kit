# block_cipher_kit

Is a small shim on top of a few block ciphers. It is useful for encrypting and decrypting data stored in files, or accessible via IOs. The main addition from using "bare" ciphers is the addition of random access reads where it can be realised.

The following ciphers are currently implemented:

* AES-256-CBC (limited random read access, requires reading to end of source)
* AES-256-CFB (limited random read access, requires reading to start offset)
* AES-256-CTR (with random read access)
* AES-256-GCM (with random read access via CTR, random read access does not validate)

Most likely ChaCha20 cam be added fairly easily.

## Interop

Data written by the schemes is compatible with the "bare" uses of the ciphers, with a few notes:

* AES-256-CBC - Same as "bare"
* AES-256-CFB - Same as "bare"
* AES-256-CTR - Same as "bare"
* AES-256-GCM - "Bare", validation tag (16 bytes) is appended at the end of the output

## Which cipher to use?

Please do some research as the topic is vast. GCM is quite good, I found CBC to be good for files as well. Be aware that both GCM and CTR have a limit of about 64GB of ciphertext before the block counter rolls over.

## Basic use

Imagine you want to encrypt some data in a streaming manner with AES-256-CTR, and data is stored in files:

```ruby
File.open(plain_file_path, "rb", "rb") do |from|
  File.open(plain_file_path + ".enc", "wb") do |into|
    scheme = BlockCipherKit::AES256CTRScheme.new(encryption_key)
    scheme.streaming_encrypt(from_plaintext_io: from, into_ciphertext_io: into)
  end
end
```

To decrypt the same file

```ruby
File.open(encrypted_file_path, "rb") do |from|
  File.open(encrypted_file_path + ".plain", "wb") do |into|
    scheme = BlockCipherKit::AES256CTRScheme.new(encryption_key)
    scheme.streaming_decrypt(from_ciphertext_io: from, into_plaintext_io: into)
  end
end
```

Note that in both of these cases:

* Only `read` will be called on the source IO (`from_ciphertext_io` and `from_plaintext_io`). They do not need to support `pos`, `seek` or `rewind`.
* Only `write` will be called on the destination IO (`to_ciphertext_io` and `to_plaintext_io`). They do not need to support `pos`, `seek` or `rewind`.

## Streaming encryption / decryption "head to tail" with blocks

To use streaming encryption, writing the plaintext the data as you go:

```
File.open(plain_file_path + ".enc", "wb") do |into|
  scheme = BlockCipherKit::AES256CTRScheme.new(encryption_key)
  scheme.streaming_encrypt(into_ciphertext_io: from) do |sink|
    sink.write("This is some very secret data")
    sink.write("Very secret indeed")
  end
end
```

The `sink` will be an object that responds to `write` (it can also be used with `IO.copy_stream`).

To use streaming decryption, reading the plaintext data as you go:

```ruby
File.open(encrypted_file_path, "rb") do |from|
  scheme = BlockCipherKit::AES256CTRScheme.new(encryption_key)
  scheme.streaming_encrypt(from_ciphertext_io: from) do |decrypted_chunk_of_plaintext|
    $stdout.puts "Decrypted: #{decrypted_chunk_of_plaintext.inspect}"
  end
end
```

## Random access reads

For random access, you can either recover a String in binary encoding:

```ruby
File.open(encrypted_file_path, "rb") do |from|
  scheme = BlockCipherKit::AES256CTRScheme.new(encryption_key)
  scheme.decrypt_range(from_ciphertext_io: from, range: 15..16) #=> "ab"
end
```

or pass an IO to receive the decrypted data:

```ruby
File.open(encrypted_file_path, "rb") do |from|
  scheme = BlockCipherKit::AES256CTRScheme.new(encryption_key)
  scheme.streaming_decrypt_range(from_ciphertext_io: from, range: 15..16, into_plaintext_io: $stdout) #=> "ab" gets printed to STDOUT
end
```

or a block (will be called for every meaningful chunk of decrypted data, repeatedly):

```ruby
File.open(encrypted_file_path, "rb") do |from|
  scheme = BlockCipherKit::AES256CTRScheme.new(encryption_key)
  scheme.streaming_decrypt_range(from_ciphertext_io: from, range: 15..) do |decrypted_chunk_of_plaintext|
    $stderr.puts "Decrypted #{decrypted_chunk_of_plaintext.inspect}"
  end
end
```

For both `streaming_decrypt_range` and `decrypt_range`:

* The source IO (`from_ciphertext_io`) **must** support `pos`, `size`, `seek` and `read`
* The destination IO must only support `write`
