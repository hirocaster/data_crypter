defmodule DataCrypterTest do
  use ExUnit.Case
  doctest DataCrypter

  def key do
    <<65, 140, 54, 116, 213, 232, 30, 177, 93, 21, 216, 252, 178, 160, 61, 241, 7,
    59, 22, 140, 113, 45, 68, 182, 137, 58, 142, 174, 125, 18, 143, 238>>
  end

  def aad do
    "additional authenticated data"
  end

  def plaintext_data do
    "will encrypt/decrypt data"
  end

  test "Support AES-GCM mode in Elang at the environment" do
    supports = :crypto.supports
    {:ciphers, ciphers} =  Enum.at(supports, 1)
    assert Enum.member?(ciphers, :aes_gcm)
  end

  test "#encrypt 256bit key" do
    {_iv, ciphertext, _ciphertag} = DataCrypter.encrypt(key(), aad(), plaintext_data())
    assert ciphertext != plaintext_data()
  end

  test "#encrypt 128bit key" do
    key_128 = DataCrypter.generate_key(16)
    {_iv, ciphertext, _ciphertag} = DataCrypter.encrypt(key_128, aad(), plaintext_data())
    assert ciphertext != plaintext_data()
  end

  test "Invalid key size at #encrypt" do
    assert_raise ArgumentError, "Invalit key size", fn ->
      DataCrypter.encrypt("Too short key", aad(), plaintext_data())
    end
    assert_raise ArgumentError, "Invalit key size", fn ->
      DataCrypter.encrypt("Too loooooooooooooooooooooong key", aad(), plaintext_data())
    end
  end

  describe "Has encrypted data" do
    defp iv do
      <<123, 29, 36, 100, 19, 34, 174, 241, 143, 115, 46, 64, 193, 250, 208, 144, 24,
        185, 170, 87, 212, 144, 235, 1, 209, 216, 162, 125, 92, 239, 105, 151>>
    end

    defp ciphertext do
      <<207, 54, 125, 93, 10, 53, 203, 194, 236, 42, 91, 81, 255, 82, 85, 86, 135,
        152, 131, 174, 76, 158, 177, 171, 5>>
    end

    defp ciphertag do
      <<198, 80, 94, 72, 136, 139, 7, 138, 145, 97, 41, 101, 201, 109, 210, 215>>
    end

    test "#decrypt" do
      assert plaintext_data() == DataCrypter.decrypt(key(), aad(), iv(), ciphertext(), ciphertag())
    end

    test "Invalid add data" do
      assert :error == DataCrypter.decrypt(key(), "Invalid add", iv(), ciphertext(), ciphertag())
    end
  end
end
