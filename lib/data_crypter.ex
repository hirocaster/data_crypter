defmodule DataCrypter do
  def generate_key(key_size \\ 32) do
    :crypto.strong_rand_bytes(key_size)
  end

  def encrypt(key, aad, data, iv_size \\ 32, cipher_type \\ :aes_gcm) do
    validate_key_size(key)

    iv = :crypto.strong_rand_bytes(iv_size)
    {ciphertext, ciphertag} = :crypto.block_encrypt(cipher_type, key, iv, { aad, data})
    { iv, ciphertext, ciphertag }
  end

  def decrypt(key, aad, iv, ciphertext, ciphertag, cipher_type \\ :aes_gcm) do
    :crypto.block_decrypt(cipher_type, key, iv, {aad, ciphertext, ciphertag})
  end

  defp validate_key_size(key) do
    case byte_size(key) do
      16 -> :ok
      32 -> :ok
      _  -> raise ArgumentError, "Invalit key size"
    end
  end
end
