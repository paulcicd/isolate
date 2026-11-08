"""SFTP/SCP operations against the authorized SSH target, never the bastion.

AsyncSSH terminates the client protocol and forwards each operation through an
authenticated upstream SFTP client. This permits file-operation audit without
interpreting file bytes as terminal output or using sudo for a subsystem.
"""

import contextlib

import asyncssh


MAX_OPEN_FILES = 64
MAX_PATH_BYTES = 16384
MAX_IO_BYTES = 262144
MAX_REQUEST_BYTES = 4 * 1024 * 1024  # AsyncSSH v3 advertised limits


def _path(value):
    if not isinstance(value, bytes) or len(value) > MAX_PATH_BYTES or b"\0" in value:
        raise asyncssh.SFTPInvalidParameter("Invalid remote path")
    return value


def _display(value):
    return value.decode("utf-8", errors="backslashreplace")[:4096]


class ProxySFTPServer(asyncssh.SFTPServer):
    """A bounded proxy whose inherited filesystem fallbacks fail closed."""

    def __init__(self, channel, server, token, client):
        super().__init__(channel)
        self.owner = server
        self.token = token
        self.client = client
        self.files = {}

    async def _event(self, operation, **fields):
        await self.owner.event("sftp_operation", channel_id=self.token,
                               operation=operation, **fields)

    async def _operation(self, operation, callback, *paths):
        for path in paths:
            _path(path)
        fields = {"path": _display(paths[0])} if paths else {}
        if len(paths) > 1:
            fields["destination_path"] = _display(paths[1])
        await self._event(operation, result="requested", **fields)
        try:
            result = await callback()
        except Exception:
            await self._event(operation, result="failed", **fields)
            raise
        await self._event(operation, result="completed", **fields)
        return result

    def map_path(self, path):
        raise asyncssh.SFTPOpUnsupported("Local filesystem access is not available")

    def reverse_map_path(self, path):
        raise asyncssh.SFTPOpUnsupported("Local filesystem access is not available")

    def open56(self, path, desired_access, flags, attrs):
        raise asyncssh.SFTPOpUnsupported("SFTP version 3 is required")

    def format_user(self, uid):
        return str(uid) if uid is not None else ""

    def format_group(self, gid):
        return str(gid) if gid is not None else ""

    async def open(self, path, pflags, attrs):
        if len(self.files) >= MAX_OPEN_FILES:
            raise asyncssh.SFTPFailure("Remote file handle limit reached")
        await self.owner.authorize("sftp")
        handle = await self._operation("open", lambda: self.client.open(
            path, pflags, attrs, encoding=None, block_size=MAX_IO_BYTES, max_requests=8), path)
        self.files[handle] = {"path": _display(path), "read_bytes": 0, "written_bytes": 0}
        return handle

    async def close(self, file_obj):
        fields = self.files.pop(file_obj, None) or {}
        try:
            await file_obj.close()
        except (asyncssh.Error, OSError):
            # On transport revocation the upstream may close before AsyncSSH
            # drains its file handles. Cleanup must still reach exit/release;
            # otherwise the parent waits forever for an already-dead channel.
            if not self.owner._finalized and not self.owner.connection.is_closed():
                raise
        finally:
            await self._event("close", result="closed", **fields)

    async def read(self, file_obj, offset, size):
        if file_obj not in self.files or offset < 0 or size < 0:
            raise asyncssh.SFTPInvalidParameter("Invalid remote file read")
        data = await file_obj.read(min(size, MAX_REQUEST_BYTES), offset)
        self.files[file_obj]["read_bytes"] += len(data)
        return data

    async def write(self, file_obj, offset, data):
        if file_obj not in self.files or offset < 0 or len(data) > MAX_REQUEST_BYTES:
            raise asyncssh.SFTPInvalidParameter("Invalid remote file write")
        count = await file_obj.write(data, offset)
        self.files[file_obj]["written_bytes"] += count
        return count

    async def fstat(self, file_obj):
        return await file_obj.stat()

    async def fsetstat(self, file_obj, attrs):
        await self._event("fsetstat", result="requested", **self.files.get(file_obj, {}))
        return await file_obj.setstat(attrs)

    async def stat(self, path):
        return await self._operation("stat", lambda: self.client.stat(path), path)

    async def lstat(self, path):
        return await self._operation("lstat", lambda: self.client.lstat(path), path)

    async def setstat(self, path, attrs):
        return await self._operation("setstat", lambda: self.client.setstat(path, attrs), path)

    async def lsetstat(self, path, attrs):
        return await self._operation("lsetstat", lambda: self.client.setstat(path, attrs, follow_symlinks=False), path)

    async def scandir(self, path):
        _path(path)
        await self._event("scandir", path=_display(path), result="requested")
        async for entry in self.client.scandir(path):
            yield entry

    async def realpath(self, path):
        return await self._operation("realpath", lambda: self.client.realpath(path), path)

    async def remove(self, path):
        return await self._operation("remove", lambda: self.client.remove(path), path)

    async def mkdir(self, path, attrs):
        return await self._operation("mkdir", lambda: self.client.mkdir(path, attrs), path)

    async def rmdir(self, path):
        return await self._operation("rmdir", lambda: self.client.rmdir(path), path)

    async def rename(self, oldpath, newpath):
        return await self._operation("rename", lambda: self.client.rename(oldpath, newpath), oldpath, newpath)

    async def posix_rename(self, oldpath, newpath):
        return await self._operation("posix_rename", lambda: self.client.posix_rename(oldpath, newpath), oldpath, newpath)

    async def readlink(self, path):
        return await self._operation("readlink", lambda: self.client.readlink(path), path)

    async def symlink(self, oldpath, newpath):
        return await self._operation("symlink", lambda: self.client.symlink(oldpath, newpath), oldpath, newpath)

    async def link(self, oldpath, newpath):
        return await self._operation("link", lambda: self.client.link(oldpath, newpath), oldpath, newpath)

    async def statvfs(self, path):
        return await self._operation("statvfs", lambda: self.client.statvfs(path), path)

    async def fstatvfs(self, file_obj):
        return await file_obj.statvfs()

    async def fsync(self, file_obj):
        return await file_obj.fsync()

    async def lock(self, file_obj, offset, length, flags):
        return await file_obj.lock(offset, length, flags)

    async def unlock(self, file_obj, offset, length):
        return await file_obj.unlock(offset, length)

    async def exit(self):
        for handle in list(self.files):
            with contextlib.suppress(Exception):
                await self.close(handle)
        self.client.exit()
        with contextlib.suppress(Exception):
            await self.client.wait_closed()
        await self.owner.release(self.token)
