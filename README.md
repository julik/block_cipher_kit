# block_cipher_kit

Is a small shim on top of a few block ciphers. It is useful for encrypting and decrypting data stored in files, or accessible via IOs. The main addition from using "bare" ciphers is the addition of random access reads where it can be realised.

The following ciphers are currently implemented:

* AES-256-CBC (limited random read access, requires reading to end of source)
* AES-256-CFB (limited random read access, requires reading to start offset)
* AES-256-CTR (with random read access)
* AES-256-GCM (with random read access via CTR, random read access does not validate)

Most likely ChaCha20 cam be added fairly easily.

The gem provides a number of **schemes** which are known, mostly correct ways to use a particular block cipher. You can use those schemes to do block encryption and decryption.

## What is a "scheme"?

A scheme is a crypto **construction** - a particular way to use a particular block cipher. In this gem, the schemes are guaranteed not to change between releases. Once a scheme is part of the gem, you will be able to use that scheme to read data you have encrypted using that scheme. Most of the **schemes** provided by the gem are constructed from standard AES block ciphers, used in a standard, transparent manner.

The following rules are true for any given Scheme:

* Ciphertext output for known plaintext, randomness source and encryption key of every scheme will come out exactly the same (a scheme encrypts deterministically).
* Plaintext output for known ciphertext and encryption key of every scheme will come out exactly the same (a scheme decrypts deterministicalle).
* The scheme's output will stay exactly the same throughout the versioning of the gem, provided the underlying cipher (OpenSSL or other) is available on the host system.

## Interop

Data written by the schemes is compatible with the "bare" uses of the ciphers, with a few notes:

* AES-256-CBC - Layout is `[ IV - 16 bytes) ][ Ciphertext in 16 byte blocks]`
* AES-256-CFB - Layout is `[ IV - 16 bytes) ][ Ciphertext in 16 byte blocks]`
* AES-256-CTR - Layout is `[ nonce - 4 bytes][ IV - 8 bytes ][ Ciphertext in 16 byte blocks]`
* AES-256-GCM - Layout is `[ nonce - 4 bytes][ IV - 8 bytes ][ Ciphertext in 16 byte blocks][ Validation tag - 16 bytes ]`
* AES-256-CFB-CIV - Layout is `[ Ciphertext in 16 byte blocks ]`. The `encryption_key` must be `[ key - 32 bytes][ IV - 16 bytes]` (the IV is not stored with ciphertext)

## Which scheme to use?

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
