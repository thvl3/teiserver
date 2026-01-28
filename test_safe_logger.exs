#!/usr/bin/env elixir

# Test SafeLogger implementation
require Logger

Logger.info("=== Test 1: Inspect format with password ==="
IO.inspect SafeLogger.sanitize(~s(%{"password" => "secret"}))

Logger.info("=== Test 2: JSON format ==="
IO.inspect SafeLogger.sanitize(~s({"password":"secret"}))

Logger.info("=== Test 3: Map with integer keys ==="
IO.inspect SafeLogger.sanitize(%{1 => "value1", 2 => "value2"})

Logger.info("=== Test 4: Configuration test ==="
Application.put_env(:teiserver, Teiserver.Logging.SafeLogger, additional_sensitive_keys: ["CUSTOM_KEY"])
Logger.info("sensitive_key?(\"custom_key\"): #{inspect SafeLogger.sensitive_key?("custom_key")}")
Logger.info("Result of sanitize with custom_key:")
IO.inspect SafeLogger.sanitize(%{"custom_key" => "secret", "other" => "value"})
