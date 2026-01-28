defmodule Teiserver.Logging.SafeLoggerTest do
  @moduledoc """
  Tests for the SafeLogger module.
  """
  use ExUnit.Case, async: true

  alias Teiserver.Logging.SafeLogger

  describe "sanitize/1 with strings" do
    test "sanitizes password in query string format" do
      input = "user=john&password=secret123"
      result = SafeLogger.sanitize(input)
      assert result == "user=john&password=[REDACTED]"
    end

    test "sanitizes password in colon format" do
      input = "user: john, password: secret123"
      result = SafeLogger.sanitize(input)
      assert result == "user: john, password=[REDACTED]"
    end

    test "sanitizes inspected Elixir map format with =>" do
      input = ~s(%{"username" => "john", "password" => "secret123"})
      result = SafeLogger.sanitize(input)
      assert result =~ ~s("username" => "john")
      assert result =~ ~s(password => [REDACTED])
      refute result =~ "secret123"
    end

    test "sanitizes JSON format with colon" do
      input = ~s({"username":"john","password":"secret123"})
      result = SafeLogger.sanitize(input)
      assert result =~ ~s("username":"john")
      assert result =~ ~s("password": "[REDACTED]")
      refute result =~ "secret123"
    end

    test "sanitizes token in various formats" do
      input = "token=abc123&api_key=xyz789"
      result = SafeLogger.sanitize(input)
      assert result == "token=[REDACTED]&api_key=[REDACTED]"
    end

    test "sanitizes Bearer token" do
      input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
      result = SafeLogger.sanitize(input)
      assert result == "Authorization: Bearer [REDACTED]"
    end

    test "sanitizes Basic auth" do
      input = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
      result = SafeLogger.sanitize(input)
      assert result == "Authorization: Basic [REDACTED]"
    end

    test "returns regular strings unchanged" do
      input = "some regular log message"
      assert SafeLogger.sanitize(input) == input
    end
  end

  describe "sanitize/1 with maps" do
    test "sanitizes maps with string keys" do
      input = %{"password" => "secret123", "username" => "john"}
      result = SafeLogger.sanitize(input)
      assert result == %{"password" => "[REDACTED]", "username" => "john"}
    end

    test "sanitizes maps with atom keys" do
      input = %{password: "secret123", username: "john"}
      result = SafeLogger.sanitize(input)
      assert result == %{password: "[REDACTED]", username: "john"}
    end

    test "sanitizes maps with mixed key types" do
      input = %{"password" => "secret123", :token => "abc123", "username" => "john"}
      result = SafeLogger.sanitize(input)
      assert result == %{"password" => "[REDACTED]", :token => "[REDACTED]", "username" => "john"}
    end

    test "sanitizes nested maps" do
      input = %{"user" => %{"password" => "secret123", "name" => "john"}}
      result = SafeLogger.sanitize(input)
      assert result == %{"user" => %{"password" => "[REDACTED]", "name" => "john"}}
    end

    test "handles maps with integer keys without crashing" do
      input = %{1 => "value1", 2 => "value2"}
      result = SafeLogger.sanitize(input)
      assert result == %{1 => "value1", 2 => "value2"}
    end

    test "handles maps with struct keys without crashing" do
      input = %{{:ok, "key"} => "value"}
      result = SafeLogger.sanitize(input)
      assert result == %{{:ok, "key"} => "value"}
    end

    test "sanitizes multiple sensitive keys" do
      input = %{
        "password" => "secret",
        "api_key" => "key123",
        "token" => "token123",
        "username" => "john"
      }

      result = SafeLogger.sanitize(input)

      assert result == %{
               "password" => "[REDACTED]",
               "api_key" => "[REDACTED]",
               "token" => "[REDACTED]",
               "username" => "john"
             }
    end
  end

  describe "sanitize/1 with keyword lists" do
    test "sanitizes keyword lists" do
      input = [password: "secret123", username: "john"]
      result = SafeLogger.sanitize(input)
      assert result == [password: "[REDACTED]", username: "john"]
    end

    test "sanitizes keyword lists with multiple sensitive keys" do
      input = [password: "secret", token: "abc123", name: "john"]
      result = SafeLogger.sanitize(input)
      assert result == [password: "[REDACTED]", token: "[REDACTED]", name: "john"]
    end
  end

  describe "sanitize/1 with lists" do
    test "sanitizes lists of maps" do
      input = [
        %{"password" => "secret1", "user" => "john"},
        %{"password" => "secret2", "user" => "jane"}
      ]

      result = SafeLogger.sanitize(input)

      assert result == [
               %{"password" => "[REDACTED]", "user" => "john"},
               %{"password" => "[REDACTED]", "user" => "jane"}
             ]
    end

    test "sanitizes lists of strings" do
      input = ["password=secret", "user=john"]
      result = SafeLogger.sanitize(input)
      assert result == ["password=[REDACTED]", "user=john"]
    end
  end

  describe "sanitize/1 with tuples" do
    test "sanitizes tuples containing sensitive data" do
      input = {:ok, %{"password" => "secret", "user" => "john"}}
      result = SafeLogger.sanitize(input)
      assert result == {:ok, %{"password" => "[REDACTED]", "user" => "john"}}
    end
  end

  describe "sanitize/1 with other types" do
    test "returns integers unchanged" do
      assert SafeLogger.sanitize(123) == 123
    end

    test "returns atoms unchanged" do
      assert SafeLogger.sanitize(:atom) == :atom
    end

    test "returns nil unchanged" do
      assert SafeLogger.sanitize(nil) == nil
    end

    test "returns floats unchanged" do
      assert SafeLogger.sanitize(3.14) == 3.14
    end
  end

  describe "sensitive_key?/1" do
    test "returns true for password as atom" do
      assert SafeLogger.sensitive_key?(:password)
    end

    test "returns true for password as string" do
      assert SafeLogger.sensitive_key?("password")
    end

    test "returns true for password with case variations" do
      assert SafeLogger.sensitive_key?("PASSWORD")
      assert SafeLogger.sensitive_key?("Password")
      assert SafeLogger.sensitive_key?("PaSsWoRd")
    end

    test "returns true for keys containing sensitive words" do
      assert SafeLogger.sensitive_key?("user_password")
      assert SafeLogger.sensitive_key?("my_api_key")
      assert SafeLogger.sensitive_key?("access_token")
    end

    test "returns false for non-sensitive keys" do
      refute SafeLogger.sensitive_key?("username")
      refute SafeLogger.sensitive_key?("email")
      refute SafeLogger.sensitive_key?("name")
    end

    test "returns false for integer keys without crashing" do
      refute SafeLogger.sensitive_key?(123)
    end

    test "returns false for other types without crashing" do
      refute SafeLogger.sensitive_key?(%{key: "value"})
      refute SafeLogger.sensitive_key?([1, 2, 3])
    end
  end

  describe "sensitive_keys/0" do
    test "returns default sensitive keys" do
      keys = SafeLogger.sensitive_keys()
      assert "password" in keys
      assert "token" in keys
      assert "api_key" in keys
    end
  end

  describe "additional_sensitive_keys configuration" do
    setup do
      # Save original config
      original_config = Application.get_env(:teiserver, Teiserver.Logging.SafeLogger, [])

      # Set test config with uppercase keys to test normalization
      Application.put_env(:teiserver, Teiserver.Logging.SafeLogger,
        additional_sensitive_keys: ["CUSTOM_SECRET", "My_API_Key"]
      )

      on_exit(fn ->
        # Restore original config
        Application.put_env(:teiserver, Teiserver.Logging.SafeLogger, original_config)
      end)

      :ok
    end

    test "normalizes additional sensitive keys to lowercase" do
      keys = SafeLogger.sensitive_keys()
      # Keys should be normalized to lowercase
      assert "custom_secret" in keys
      assert "my_api_key" in keys
    end

    test "matches additional sensitive keys regardless of case in input" do
      # The configured keys are uppercase, but should be normalized
      assert SafeLogger.sensitive_key?("CUSTOM_SECRET")
      assert SafeLogger.sensitive_key?("custom_secret")
      assert SafeLogger.sensitive_key?("Custom_Secret")
      assert SafeLogger.sensitive_key?("My_API_Key")
    end

    test "sanitizes maps with additional sensitive keys" do
      input = %{"CUSTOM_SECRET" => "secret123", "username" => "john"}
      result = SafeLogger.sanitize(input)
      assert result == %{"CUSTOM_SECRET" => "[REDACTED]", "username" => "john"}
    end

    test "ignores non-string values in additional_sensitive_keys" do
      # Save original config
      original_config = Application.get_env(:teiserver, Teiserver.Logging.SafeLogger, [])

      # Set config with mixed types (should filter out non-strings)
      Application.put_env(:teiserver, Teiserver.Logging.SafeLogger,
        additional_sensitive_keys: ["valid_key", :atom_key, 123, %{invalid: "map"}]
      )

      # Should only include the valid string key
      keys = SafeLogger.sensitive_keys()
      assert "valid_key" in keys
      refute :atom_key in keys
      refute 123 in keys

      # Restore config
      Application.put_env(:teiserver, Teiserver.Logging.SafeLogger, original_config)
    end
  end

  describe "logger functions" do
    test "info/1 sanitizes the message" do
      # This test just ensures the function doesn't crash
      # Actual logging behavior is tested by Logger
      assert :ok = SafeLogger.info("password=secret")
    end

    test "debug/1 sanitizes the message" do
      assert :ok = SafeLogger.debug("password=secret")
    end

    test "warning/1 sanitizes the message" do
      assert :ok = SafeLogger.warning("password=secret")
    end

    test "error/1 sanitizes the message" do
      assert :ok = SafeLogger.error("password=secret")
    end
  end
end
