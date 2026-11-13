"""Black-box shell checks with stub package/network commands. Never runs apt on host."""
import os
import shutil
from pathlib import Path
import subprocess
import pytest

SCRIPT=Path(__file__).parents[1]/'tools/install-termux.sh'

def _bash():
    """Prefer a POSIX bash: on Windows System32/bash.exe is WSL and rejects Windows paths."""
    override=os.environ.get('WIFIT3_TEST_BASH')
    if override: return override
    if os.name=='nt':
        for candidate in (r'C:\Program Files\Git\bin\bash.exe', r'C:\Program Files\Git\usr\bin\bash.exe'):
            if os.path.exists(candidate): return candidate
    return shutil.which('bash') or 'bash'

BASH=_bash()

# Commands are injected as bash FUNCTIONS via BASH_ENV (non-interactive shells read it).
# PATH stubs cannot beat Git Bash, which prepends its own /mingw64/bin (real git/curl)
# ahead of any inherited PATH; functions outrank every PATH lookup.
STUBS='''apt(){ echo "apt $*" >> "$LOG"
 if [ "${FAIL_APT:-}" = 1 ]; then exit 2; fi
}
curl(){ echo "curl $*" >> "$LOG"
 if [ "${FAIL_CURL:-}" = 1 ]; then echo 'CANNOT LINK EXECUTABLE libcurl.so' >&2; return 1; fi
 echo 'curl mock'
}
git(){ echo "git $*" >> "$LOG"
 if [ "$1" = ls-remote ]; then
  if [ "${FAIL_GIT:-}" = 1 ]; then echo 'CANNOT LINK EXECUTABLE git-remote-https libcurl.so' >&2; exit 128; fi
  echo 'mockhash HEAD'; return 0
 fi
 if [ "$1" = clone ]; then
  for last in "$@"; do :; done
  mkdir -p "$last/.git"; return 0
 fi
 if [ "${3:-}" = remote ]; then echo 'https://github.com/OliverRhyme/wifit3-termux.git'; fi
}
python(){ echo "python $*" >> "$LOG"
 if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$3/bin"
  printf '#!/bin/bash\\necho "pip $*" >> "$LOG"\\n' > "$3/bin/python"
  chmod +x "$3/bin/python"
 fi
}
dpkg-query(){ echo "diagnostics packages"; }
apt-mark(){ echo "diagnostics holds"; }
'''

@pytest.fixture
def sandbox(tmp_path):
    home=tmp_path/'home';home.mkdir()
    prefix=tmp_path/'prefix';prefix.mkdir()
    stubs=tmp_path/'stubs.sh'
    stubs.write_text(STUBS,newline='')
    log=tmp_path/'operations'
    env={**os.environ,'HOME':home.as_posix(),'PREFIX':prefix.as_posix(),'TERMUX_VERSION':'mock',
         'LOG':log.as_posix(),'BASH_ENV':stubs.as_posix()}
    def run(answer='YES\n',args=(),**overrides):
        # Bytes stdin: text mode would translate \n to \r\n on Windows and break `read -r`.
        result=subprocess.run([BASH,SCRIPT.as_posix(),*args],input=answer.encode(),capture_output=True,env={**env,**overrides})
        result.stdout=result.stdout.decode(errors='replace')
        result.stderr=result.stderr.decode(errors='replace')
        operations=log.read_text().splitlines() if log.exists() else []
        return result,operations
    return run,home,prefix


def test_cancel_before_package_changes(sandbox):
    run,home,prefix=sandbox
    result,ops=run(answer='NO\n')
    assert result.returncode==0 and ops==[]
    assert not (home/'.local').exists()


def test_full_upgrade_precedes_dependencies_and_network(sandbox):
    run,home,prefix=sandbox
    result,ops=run()
    assert result.returncode==0, result.stderr
    assert ops[:3]==['apt update','apt full-upgrade','apt install python libusb termux-api git curl ca-certificates']
    assert not any(' -y' in x for x in ops)
    check=next(i for i,x in enumerate(ops) if x.startswith('git ls-remote '))
    clone=next(i for i,x in enumerate(ops) if x.startswith('git clone '))
    assert check<clone
    assert (home/'.local/share/wifit3-mobile/upstream/.git').is_dir()
    assert (prefix/'bin/wifit3-mobile-service').is_file()


def test_apt_error_prevents_clone(sandbox):
    run,_,_=sandbox
    result,ops=run(FAIL_APT='1')
    assert result.returncode!=0 and ops==['apt update']


def test_broken_git_helper_prevents_checkout_and_runtime(sandbox):
    run,home,prefix=sandbox
    result,ops=run(FAIL_GIT='1')
    assert result.returncode!=0 and 'CANNOT LINK EXECUTABLE' in result.stderr
    assert not any(x.startswith('git clone') for x in ops)
    assert not (prefix/'bin/wifit3-mobile-service').exists()


def test_check_mode_is_read_only_for_package_manager(sandbox):
    run,home,prefix=sandbox
    result,ops=run(args=('--check',),answer='')
    assert result.returncode==0
    assert not any(x.startswith('apt ') for x in ops)
    assert any(x.startswith('git ls-remote') for x in ops)
    assert not (home/'.local').exists()
