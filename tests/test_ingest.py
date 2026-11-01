from app.ingest import (HashLine, ingest_zip, normalize_22000, parse_16800,
                        parse_22000, parse_hccapx, targets_of, unpack_zip)
from conftest import VALID_16800, VALID_EAPOL, VALID_FT, VALID_PMKID


class TestParse22000:
    def test_valid_eapol(self):
        hl = parse_22000(VALID_EAPOL)
        assert hl and hl.kind == "eapol"
        assert hl.bssid == "a4:a1:c2:b3:d4:e5"
        assert hl.ssid == "HomeNet"

    def test_valid_pmkid(self):
        hl = parse_22000(VALID_PMKID)
        assert hl and hl.kind == "pmkid"

    def test_ft_line_is_recognized(self):
        hl = parse_22000(VALID_FT)
        assert hl  # валидна, но фильтруется на этапе extract (ft_count)

    def test_uppercase_normalized(self):
        up = VALID_PMKID.replace("a4a1c2b3d4e5", "A4A1C2B3D4E5").replace(
            "9e0d8e37a6542d7eef28df75a148d91b", "9E0D8E37A6542D7EEF28DF75A148D91B")
        hl = parse_22000(up)
        assert hl.raw == VALID_PMKID

    def test_bad_pmkid_length(self):
        bad = VALID_PMKID.replace("9e0d8e37a6542d7eef28df75a148d91b", "9e0d8e37")
        assert parse_22000(bad) is None

    def test_bad_mac(self):
        bad = VALID_PMKID.replace("*a4a1c2b3d4e5*", "*a4a1c2b3d4eZ*")
        assert parse_22000(bad) is None

    def test_wrong_field_count(self):
        assert parse_22000("WPA*02*only*three") is None

    def test_wrong_prefix(self):
        assert parse_22000("HCPX*02*...") is None

    def test_hidden_ssid_rejected(self):
        bad = VALID_PMKID.replace("*486f6d654e6574*", "*")
        assert parse_22000(bad) is None


class TestConversions:
    def test_16800_to_22000(self):
        hl = parse_16800(VALID_16800)
        assert hl and hl.kind == "pmkid" and hl.ssid == "GuestAP"
        assert hl.raw.startswith("WPA*01*47f1db3bf638231850a166447fb26483*")

    def test_hccapx(self):
        import struct
        mac_ap = bytes.fromhex("a4a1c2b3d4e5")
        mac_sta = bytes.fromhex("f0e1d2c3b4a5")
        nonce = bytes(range(32))
        eapol = bytes.fromhex("0103007702010a01000000") + b"\x00" * 245
        essid = b"HomeNet"
        rec = (b"HCPX" + bytes([4, 0x02]) + mac_ap + nonce + mac_sta +
               struct.pack("<H", len(eapol)) + eapol.ljust(256, b"\x00") +
               bytes([len(essid)]) + essid.ljust(32, b"\x00") +
               bytes(range(16)))
        lines = parse_hccapx(rec * 2)
        assert len(lines) == 2
        assert lines[0].ssid == "HomeNet" and lines[0].kind == "eapol"


class TestZip:
    def _zip_bytes(self, names: dict[str, bytes]) -> bytes:
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in names.items():
                zf.writestr(name, data)
        return buf.getvalue()

    def test_unpack_whitelist(self, tmp_path):
        data = self._zip_bytes({
            "a.hc22000": VALID_PMKID.encode(),
            "junk.exe": b"MZ",
            "b.PCAP": b"\xd4\xc3\xb2\xa1garbage",
        })
        files = unpack_zip(data, 512, 64)
        assert len(files) == 2
        assert {f.suffix.lower() for f in files} == {".hc22000", ".pcap"}

    def test_zip_slip_blocked(self, tmp_path):
        data = self._zip_bytes({"../../etc/evil.hc22000": b"x"})
        assert unpack_zip(data, 512, 64) == []

    def test_dedup_and_targets(self, tmp_path):
        data = self._zip_bytes({"a.hc22000": (VALID_PMKID + "\n" + VALID_PMKID).encode()})
        res = ingest_zip(data, 512, 64)
        assert len(res.lines) == 1
        t = targets_of(res.lines)
        assert t == [{"ssid": "HomeNet", "bssid": "a4:a1:c2:b3:d4:e5", "kind": "pmkid", "count": 1}]

    def test_bomb_guard(self, tmp_path):
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            info = zipfile.ZipInfo("big.hc22000")
            info.file_size = 10 * 1024 * 1024
            zf.writestr(info, b"0" * (10 * 1024 * 1024))
        try:
            ingest_zip(buf.getvalue(), 512, 1)  # лимит 1 МБ
            assert False, "должен был отвергнуть по размеру"
        except ValueError:
            pass
