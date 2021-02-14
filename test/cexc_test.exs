defmodule CexcTest do
  use ExUnit.Case

  test "8-bit un-reflected generate CRC" do
    crc_defn = Cexc.init(:crc8)
    assert Cexc.calc_crc('123456789', crc_defn) == 0xF4
  end

  test "8-bit reflected generate CRC" do
    crc_defn = Cexc.init(:crc8_rohc)
    assert Cexc.calc_crc('123456789', crc_defn) == 0xD0
  end

  test "8-bit Sensirion CRC" do
    crc_defn = Cexc.init(:crc8_sensirion)
    assert Cexc.calc_crc([0xBE, 0xEF], crc_defn) == 0x92
  end

  test "16-bit un-reflected generate CRC" do
    crc_defn = Cexc.init(:crc16_aug_ccitt)
    assert Cexc.calc_crc('123456789', crc_defn) == 0xE5CC
  end

  test "16-bit un-reflected check CRC" do
    crc_defn = Cexc.init(:crc16_aug_ccitt)

    assert Cexc.calc_crc(
             [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xE5, 0xCC],
             crc_defn
           ) == 0
  end

  test "16-bit reflected generate CRC" do
    crc_defn = Cexc.init(:crc16_usb)
    assert Cexc.calc_crc('123456789', crc_defn) == 0xB4C8
  end

  test "32-bit un-reflected generate CRC" do
    crc_defn = Cexc.init(:crc32_bzip2)
    assert Cexc.calc_crc('123456789', crc_defn) == 0xFC891918
  end

  test "32-bit reflected generate CRC" do
    crc_defn = Cexc.init(:crc32)
    assert Cexc.calc_crc('123456789', crc_defn) == 0xCBF43926
  end

  test "64-bit un-reflected generate CRC" do
    crc_defn = Cexc.init(:crc64_ecma_182)
    assert Cexc.calc_crc('123456789', crc_defn) == 0x6C40DF5F0B497347
  end

  test "64-bit reflected generate CRC" do
    crc_defn = Cexc.init(:crc64_go_iso)
    assert Cexc.calc_crc('123456789', crc_defn) == 0xB90956C775A41001
  end

  test "16-bit random reflected generate CRC" do
    crc_defn = Cexc.init({16, 0x1234, 0, 0, true})
    assert Cexc.calc_crc('123456789', crc_defn) == 0xF13
  end

  test "16-bit random reflected check CRC" do
    crc_defn = Cexc.init({16, 0x1234, 0, 0, true})

    assert Cexc.calc_crc(
             [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x13, 0x0F],
             crc_defn
           ) == 0
  end
end
