"""Explicit versioned releases; application state and secrets are never restored.

The installer selects code for the next process start. It does not restart a
live service, initialize a database, change IdP settings or copy runtime data.
"""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
import venv


class InstallError(ValueError):
    pass


MANIFEST_SCHEMA = 1
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]{0,63})?\Z")
CODE_DIRECTORIES = ("shared", "scripts", "wrappers")
CODE_FILES = ("requirements.txt", "LICENSE", "LICENSE.md", "COPYING")
SECRET_NAMES = frozenset(("password", "client_secret", "private_key", "access_token", "refresh_token",
    "secret_access_key", "aws_secret_access_key", "token", "secret_key"))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _hash(path):
    result = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def _absolute(path):
    value = Path(path)
    if not value.is_absolute() or any(item.is_symlink() for item in (value, *value.parents)):
        raise InstallError("release paths must be explicit absolute paths without symlinks")
    return value.resolve()


def _root(path, create=False):
    root = _absolute(path)
    if root == Path(root.anchor):
        raise InstallError("a filesystem root cannot be an installation root")
    if create:
        root.mkdir(mode=0o755, parents=True, exist_ok=True)
        (root / "releases").mkdir(mode=0o755, exist_ok=True)
    if (root / "releases").is_symlink():
        raise InstallError("release directory cannot be a symlink")
    if root.exists() and os.name == "posix":
        info = root.stat()
        if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            raise InstallError("installation root requires trusted ownership and no group/world writes")
    return root


def _version(version):
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise InstallError("release version must be a numeric semantic version")
    return version


def _private_config(path, root, service_user="auth"):
    path = _absolute(path)
    if not path.is_file() or root / "releases" in path.parents:
        raise InstallError("configuration must be an existing file outside release directories")
    info = path.stat()
    owners = {0, os.geteuid()} if os.name == "posix" else set()
    if os.name == "posix" and os.geteuid() == 0 and service_user:
        import pwd
        try:
            owners.add(pwd.getpwnam(service_user).pw_uid)
        except KeyError:
            raise InstallError("intended service identity does not exist") from None
    if os.name == "posix" and (info.st_uid not in owners or info.st_mode & 0o077):
        raise InstallError("configuration must be root/operator-owned and owner-only")
    if os.name == "posix":
        for parent in path.parents:
            ancestor = parent.lstat()
            sticky = ancestor.st_uid == 0 and ancestor.st_mode & stat.S_ISVTX
            if ancestor.st_uid not in owners or ancestor.st_mode & 0o022 and not sticky:
                raise InstallError("configuration ancestors require trusted ownership and no group/world writes")
            if sticky:
                break
    import yaml
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, UnicodeError):
        raise InstallError("deployment configuration is malformed; inspect the private file locally") from None
    if not isinstance(value, dict):
        raise InstallError("configuration must be an object")
    def visit(current, prefix=""):
        if isinstance(current, dict):
            for key, item in current.items():
                name = str(key)
                if name.lower() in SECRET_NAMES and item:
                    raise InstallError("inline credentials are not accepted: " + prefix + name)
                visit(item, prefix + name + ".")
        elif isinstance(current, list):
            for item in current:
                visit(item, prefix)
    visit(value)
    return path


def _source_files(source):
    source = _absolute(source)
    files = []
    for directory in CODE_DIRECTORIES:
        base = source / directory
        if not base.is_dir() or base.is_symlink():
            raise InstallError("release source is missing an application directory")
        for path in base.rglob("*"):
            if any(part == "__pycache__" or part.startswith(".tmp-") for part in path.parts):
                continue
            if path.is_symlink():
                raise InstallError("release source must not contain symlinks")
            if path.is_file() and path.suffix not in (".pyc", ".pyo"):
                files.append(path)
    for name in CODE_FILES:
        path = source / name
        if path.is_symlink():
            raise InstallError("release source must not contain symlinks")
        if path.is_file():
            files.append(path)
    if not (source / "requirements.txt").is_file() or not (source / "scripts" / "isolate-service.py").is_file():
        raise InstallError("source requires runtime requirements and the unified service launcher")
    requirements = (source / "requirements.txt").read_text(encoding="utf-8")
    if re.search(r"https?://[^\s/]+:[^\s@]+@", requirements):
        raise InstallError("requirements must not contain repository credentials")
    return source, sorted(files)


def plan_release(root, source, version, config, service_user="auth"):
    root, version = _root(root), _version(version)
    config = _private_config(config, root, service_user)
    source, files = _source_files(source)
    if source == root or any((source / directory) == root or (source / directory) in root.parents for directory in CODE_DIRECTORIES):
        raise InstallError("installation root cannot overlap a copied source directory")
    records = {path.relative_to(source).as_posix(): _hash(path) for path in files}
    return {"version": version, "destination": str(root / "releases" / version), "config": str(config),
        "file_count": len(records), "source_sha256": hashlib.sha256(_canonical(records)).hexdigest(),
        "files": records, "state_migration": False, "restart_services": False}


def _write_json(path, value, mode=0o600):
    temporary = path.parent / (".write-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(_canonical(value) + b"\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextlib.contextmanager
def _lock(root):
    descriptor = os.open(root / ".release.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InstallError("invalid installation lock")
        if os.name == "posix":
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:
            import msvcrt
            if not os.fstat(descriptor).st_size:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, 0)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        yield
    finally:
        os.close(descriptor)


def _environment(release):
    directory = release / ".venv"
    venv.EnvBuilder(with_pip=True, symlinks=os.name == "posix").create(directory)
    python = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    command = [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--require-virtualenv", "-r", str(release / "requirements.txt")]
    result = subprocess.run(command, capture_output=True, timeout=900, check=False)
    if result.returncode:
        raise InstallError("release dependency installation failed; no activation occurred")
    freeze = subprocess.run([str(python), "-m", "pip", "freeze", "--all"], capture_output=True, timeout=60, check=True).stdout
    return freeze.decode("utf-8")


def _dependency_inventory(release):
    directory = release / ".venv"
    if not directory.is_dir() or directory.is_symlink():
        raise InstallError("release virtual environment is missing")
    return {path.relative_to(directory).as_posix():
        {"link": os.readlink(path)} if path.is_symlink() else {"sha256": _hash(path)}
        for path in sorted(directory.rglob("*")) if path.is_symlink() or path.is_file()}


def stage_release(root, source, version, config, expected_source_sha256, dependency_installer=None, service_user="auth"):
    plan = plan_release(root, source, version, config, service_user)
    if not re.fullmatch(r"[a-f0-9]{64}", str(expected_source_sha256)) or plan["source_sha256"] != expected_source_sha256:
        raise InstallError("source differs from the reviewed installation plan")
    root = _root(root, create=True)
    with _lock(root):
        destination = root / "releases" / version
        if destination.exists():
            raise InstallError("release version already exists; immutable releases cannot be overwritten")
        # Virtual environments contain absolute paths. Build at the final path;
        # only release.json marks a completed, selectable immutable release.
        temporary = destination
        temporary.mkdir(mode=0o755)
        try:
            for name, digest in plan["files"].items():
                original, target = Path(source) / name, temporary / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, target, follow_symlinks=False)
                if target.is_symlink() or _hash(target) != digest:
                    raise InstallError("source changed while staging; release was not accepted")
                target.chmod(0o555 if name.endswith((".sh", ".py")) else 0o444)
            freeze = (dependency_installer or _environment)(temporary)
            (temporary / "dependencies.txt").write_text(freeze, encoding="utf-8")
            (temporary / "dependencies.txt").chmod(0o444)
            # Schema capabilities come from candidate source, not the running
            # installer's imports. No candidate Python is executed for this read.
            state_source = (temporary / "shared" / "isolate_state.py").read_text(encoding="utf-8")
            match = re.search(r"^SCHEMA_VERSION\s*=\s*([0-9]+)\s*$", state_source, re.M)
            if not match:
                raise InstallError("candidate SQL schema compatibility is missing")
            schema = int(match[1])
            manifest = {"schema": MANIFEST_SCHEMA, "version": version, "source_sha256": plan["source_sha256"],
                "files": plan["files"], "dependency_sha256": _hash(temporary / "dependencies.txt"),
                "environment": _dependency_inventory(temporary),
                "state_schema_min": schema, "state_schema_max": schema, "created_at": time.time()}
            _write_json(temporary / "release.json", manifest, 0o444)
            return {"staged": True, "version": version, "source_sha256": plan["source_sha256"],
                "release_sha256": _hash(destination / "release.json"), "path": str(destination)}
        except BaseException:
            # Keep a failed, unselectable release directory for diagnosis. Never
            # recursively delete a caller-derived path or modify active code.
            raise


def verify_release(root, version, expected_release_sha256):
    root, version = _root(root), _version(version)
    release = root / "releases" / version
    if release.is_symlink() or not release.is_dir():
        raise InstallError("release is missing or has an unsafe path")
    path = release / "release.json"
    if path.is_symlink() or _hash(path) != expected_release_sha256:
        raise InstallError("release manifest differs from its reviewed checksum")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("version") != version:
        raise InstallError("unsupported release manifest")
    if hashlib.sha256(_canonical(manifest["files"])).hexdigest() != manifest["source_sha256"]:
        raise InstallError("invalid source inventory checksum")
    _, actual_files = _source_files(release)
    if {item.relative_to(release).as_posix() for item in actual_files} != set(manifest["files"]):
        raise InstallError("release source inventory has changed")
    for directory in CODE_DIRECTORIES:
        if any(path.suffix in (".pyc", ".pyo") or path.is_symlink()
                for path in (release / directory).rglob("*")):
            raise InstallError("unexpected bytecode or symlink in staged source")
    for name, digest in manifest["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or str(relative).startswith("."):
            raise InstallError("unsafe manifest file path")
        target = release / relative
        if target.is_symlink() or release not in target.resolve().parents or _hash(target) != digest:
            raise InstallError("staged source is missing or modified")
    if _hash(release / "dependencies.txt") != manifest["dependency_sha256"]:
        raise InstallError("dependency inventory was modified")
    if _dependency_inventory(release) != manifest["environment"]:
        raise InstallError("release virtual environment was modified")
    return manifest


PROBE = r'''
import hashlib,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from isolate_config import load_config
from isolate_setup import diagnose
config=load_config(path=sys.argv[2],use_env=False)
result=diagnose(config)
from isolate_oidc import identity_provider_config
from isolate_identity_binding import provider_binding
provider=identity_provider_config(config)
authority={"backend":config.get("state",{}).get("backend","redis")}
authority["identity_binding"]=provider_binding(config)["fingerprint"]
identity={k:provider.get(k) for k in ("provider","issuer","client_id","expected_audience","token_kind","claim_mapping")}
authority["identity_configuration"]=hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()
if authority["backend"] != "redis":
 from isolate_state import SQLState
 metadata=SQLState(config["state"]).metadata()
 authority.update({k:metadata.get(k) for k in ("schema_version","generation","epoch")})
else:
 redis=config.get("redis",{})
 authority["location"]={k:redis.get(k) for k in ("host","port","db","sentinel_master")}
keys={}
for section,key in (("recordings","signing_key_file"),("command_execution","signing_key_file"),("dashboard","secret_key_file"),("gateway","host_key_file"),("policy_as_code","approval_key_file")):
 path=config.get(section,{}).get(key)
 if path and Path(path).is_file(): keys[section+"."+key]=hashlib.sha256(Path(path).read_bytes()).hexdigest()
path=config.get("logging",{}).get("integrity",{}).get("key_file")
if path and Path(path).is_file(): keys['logging.integrity.key_file']=hashlib.sha256(Path(path).read_bytes()).hexdigest()
print(json.dumps({"ok":result.get("ok") is True,"authority":authority,"issuer":provider.get("issuer"),"keys":keys}))
'''


def probe_release(release, config, service_user="auth"):
    python = release / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        raise InstallError("candidate virtual environment is missing")
    before = None
    if os.name == "posix" and service_user:
        import pwd
        account = pwd.getpwnam(service_user)
        if os.geteuid() == 0:
            def before():
                os.setgroups([])
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)
        elif os.geteuid() != account.pw_uid:
            raise InstallError("preflight must run as the intended service identity")
    try:
        result = subprocess.run([str(python), "-I", "-B", "-c", PROBE, str(release / "shared"), str(config)],
            capture_output=True, text=True, timeout=90, check=False, preexec_fn=before)
        value = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise InstallError("candidate preflight could not complete") from exc
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise InstallError("candidate config, identity provider or dependencies are unhealthy")
    return value


def status(root):
    root = _root(root)
    if os.name == "posix":
        pointer = root / "current"
        if not pointer.is_symlink():
            if pointer.exists():
                raise InstallError("current must be an installer-owned symlink")
            return {"active": None, "root": str(root)}
        selection = pointer.resolve()
        if selection.parent != root / "activation-history" or not re.fullmatch(r"[a-f0-9]{32}", selection.name):
            raise InstallError("unsafe activation pointer")
        path = selection / "selection.json"
    else:
        path = root / "current.json"
    if not path.exists():
        return {"active": None, "root": str(root)}
    if path.is_symlink():
        raise InstallError("unsafe activation pointer")
    value = json.loads(path.read_text(encoding="utf-8"))
    _version(value["version"])
    return dict(value, root=str(root))


def activate_release(root, version, config, expected_release_sha256, service_user="auth", probe=None, rollback=False):
    root = _root(root, create=True)
    config = _private_config(config, root, service_user)
    with _lock(root):
        manifest = verify_release(root, version, expected_release_sha256)
        release = root / "releases" / version
        check = probe or probe_release
        candidate = check(release, config, service_user)
        if candidate.get("ok") is not True:
            raise InstallError("candidate health checks failed")
        schema = candidate.get("authority", {}).get("schema_version")
        if schema is not None and not manifest["state_schema_min"] <= int(schema) <= manifest["state_schema_max"]:
            raise InstallError("release cannot read the current authoritative state schema")
        current = status(root)
        if current.get("version"):
            if Path(current["config"]) != config:
                raise InstallError("change the external configuration separately from release activation")
            verify_release(root, current["version"], current["release_sha256"])
            observed = check(root / "releases" / current["version"], config, service_user)
            if observed.get("ok") is not True or any(candidate.get(key) != observed.get(key) for key in ("authority", "issuer", "keys")):
                raise InstallError("candidate changes authority, identity issuer or persistent signing keys")
        selection = {"version": version, "release_sha256": expected_release_sha256,
            "config": str(config), "previous_version": current.get("version"),
            "activated_at": time.time(), "operation": "rollback" if rollback else "activate",
            "authority": candidate.get("authority")}
        history = root / "activation-history"
        if history.is_symlink():
            raise InstallError("unsafe activation history path")
        history.mkdir(mode=0o755, exist_ok=True)
        identifier = uuid.uuid4().hex
        if os.name == "posix":
            # Selection metadata and code paths live behind one atomic pointer.
            # A crash before replacement leaves the previous selection intact.
            selected = history / identifier
            selected.mkdir(mode=0o755)
            for name in (*CODE_DIRECTORIES, ".venv", "requirements.txt"):
                os.symlink(str(Path("../..") / "releases" / version / name), selected / name,
                    target_is_directory=name in (*CODE_DIRECTORIES, ".venv"))
            _write_json(selected / "selection.json", selection, 0o644)
            link = root / (".current-" + uuid.uuid4().hex)
            os.symlink(str(Path("activation-history") / identifier), link, target_is_directory=True)
            try:
                if (root / "current").exists() and not (root / "current").is_symlink():
                    raise InstallError("current must be an installer-owned symlink")
                os.replace(link, root / "current")
            finally:
                if link.is_symlink():
                    link.unlink()
        else:
            _write_json(history / (identifier + ".json"), selection)
            _write_json(root / "current.json", selection)
        return dict(selection, selected=True, restart_services=False, database_restored=False)


def rollback_release(root, version, config, expected_release_sha256, service_user="auth", probe=None):
    if not status(root).get("version"):
        raise InstallError("there is no active release to roll back")
    return activate_release(root, version, config, expected_release_sha256, service_user, probe, rollback=True)
