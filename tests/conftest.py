import os
import sys
import tempfile
from pathlib import Path

# env до импорта app-модулей
_TMP = tempfile.mkdtemp(prefix="crackd-test-")
os.environ["CRACKD_DATA"] = _TMP
os.environ["DRY_RUN"] = "1"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["ADMIN_PASSWORD"] = "testpass"
os.environ["CRACKD_CONFIG"] = str(Path(__file__).parent / "test_config.yaml")
sys.path.insert(0, str(Path(__file__).parent.parent / "server"))

VALID_EAPOL = ("WPA*02*63d3d6c517aa54d7d305d014e90e6ca6*a4a1c2b3d4e5*f0e1d2c3b4a5*"
               "486f6d654e6574*68ae10f0c4534bd6dec7d13590acc41019d8f0b67f55bffd63e9fd8751bb4744*"
               "0103007702010a67559060bb08d53ebd623996d15740072890f26997f2da69b17f72d01c32901"
               "402f89b5a3d20410f6366ee9e95d15aad238d*02")
VALID_PMKID = "WPA*01*9e0d8e37a6542d7eef28df75a148d91b*a4a1c2b3d4e5*f0e1d2c3b4a5*486f6d654e6574***"
VALID_FT = ("WPA*03*602741e43c4f9816052739d32a635d81*a4a1c2b3d4e5*f0e1d2c3b4a5*"
            "486f6d654e6574****04ab*1122*3344")
VALID_16800 = "47f1db3bf638231850a166447fb26483*a4a1c2b3d4e5*f0e1d2c3b4a5*47756573744150"
