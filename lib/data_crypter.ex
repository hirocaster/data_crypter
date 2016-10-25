defmodule DataCrypter do
  @moduledoc """
  AES 128/256 GCM encrypt/decrypt(Erlang crypto function) wrapper module for Elixir.
  """

  @spec generate_key(integer) :: binary
  def generate_key(key_size \\ 32) when is_integer(key_size) do
    :crypto.strong_rand_bytes(key_size)
  end

  @spec encrypt(binary, binary, binary, integer, atom) :: {binary, binary, binary}
  def encrypt(key, aad, data, iv_size \\ 32, cipher_type \\ :aes_gcm) when is_integer(iv_size) and is_atom(cipher_type) do
    validate_key_size(key)

    iv = :crypto.strong_rand_bytes(iv_size)
    {ciphertext, ciphertag} = :crypto.block_encrypt(cipher_type, key, iv, { aad, data})
    { iv, ciphertext, ciphertag }
  end

  @spec decrypt(binary, binary, binary, binary, binary, atom) :: binary
  def decrypt(key, aad, iv, ciphertext, ciphertag, cipher_type \\ :aes_gcm) when is_atom(cipher_type) do
    :crypto.block_decrypt(cipher_type, key, iv, {aad, ciphertext, ciphertag})
  end

  @spec validate_key_size(binary) :: atom
  defp validate_key_size(key) when is_binary(key) do
    case byte_size(key) do
      16 -> :ok
      32 -> :ok
      _  -> raise ArgumentError, "Invalit key size"
    end
  end
end
