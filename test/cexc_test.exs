defmodule Cexc8BitUnReflectedTest do
  use ExUnit.Case
  use Cexc, "CRC8"

  test "8-bit un-reflected generate CRC" do
    assert crc('123456789') == 0xF4
  end
end

defmodule Cexc8BitReflectedTest do
  use ExUnit.Case
  use Cexc, "CRC8_ROHC"

  test "8-bit reflected generate CRC" do
    assert crc('123456789') == 0xD0
  end
end

defmodule Cexc16BitUnReflectedTest do
  use ExUnit.Case
  use Cexc, "CRC16_AUG_CCITT"

  test "16-bit un-reflected generate CRC" do
    assert crc('123456789') == 0xE5CC
  end

  test "16-bit un-reflected check CRC" do
    assert crc([0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0xE5,0xCC]) == 0
  end
end

defmodule Cexc16BitReflectedTest do
  use ExUnit.Case
  use Cexc, "CRC16_USB"

  test "16-bit reflected generate CRC" do
    assert crc('123456789') == 0xB4C8
  end
end

defmodule Cexc32BitUnReflectedTest do
  use ExUnit.Case
  use Cexc, "CRC32_BZIP2"

  test "32-bit un-reflected generate CRC" do
    assert crc('123456789') == 0xFC891918
  end
end

defmodule Cexc32BitReflectedTest do
  use ExUnit.Case
  use Cexc, "CRC32"

  test "32-bit reflected generate CRC" do
    assert crc('123456789') == 0xCBF43926
  end
end

defmodule Cexc64BitUnReflectedTest do
  use ExUnit.Case
  use Cexc, "CRC64_ECMA_182"

  test "64-bit un-reflected generate CRC" do
    assert crc('123456789') == 0x6C40DF5F0B497347
  end
end

defmodule Cexc64BitReflectedTest do
  use ExUnit.Case
  use Cexc, "CRC64_GO_ISO"

  test "64-bit reflected generate CRC" do
    assert crc('123456789') == 0xB90956C775A41001
  end
end

defmodule CexcRandomAlgorithmTest do
  use ExUnit.Case
  use Cexc, {16, 0x1234, 0, 0, true}

  test "16-bit random reflected generate CRC" do
    assert crc('123456789') == 0xF13
  end

  test "16-bit random reflected check CRC" do
    assert crc([0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x13,0x0F]) == 0
  end
end
