# SPDX-License-Identifier: LGPL-3.0-or-later
from contextlib import AbstractContextManager
from typing import Any, ClassVar, Iterator, Self, final
from enum import IntEnum, StrEnum

@final
class NssSource(StrEnum):
    FILES = "FILES"
    SSS = "SSS"
    WINBIND = "WINBIND"

class NssModule(IntEnum):
    FILES = 0
    SSS = 1
    WINBIND = 2
    ALL = -1

class NssReturnCode(IntEnum):
    TRYAGAIN = -2
    UNAVAIL = -1
    NOTFOUND = 0
    SUCCESS = 1
    RETURN = 2

class NssError(Exception):
    errno: int
    nssop: str
    return_code: int
    module: str

@final
class PasswdResult(tuple[Any, ...]):
    n_sequence_fields: ClassVar[int]
    n_fields: ClassVar[int]
    n_unnamed_fields: ClassVar[int]
    @property
    def pw_name(self) -> str: ...
    @property
    def pw_uid(self) -> int: ...
    @property
    def pw_gid(self) -> int: ...
    @property
    def pw_gecos(self) -> str: ...
    @property
    def pw_dir(self) -> str: ...
    @property
    def pw_shell(self) -> str: ...
    @property
    def source(self) -> NssSource: ...
    @property
    def local(self) -> bool: ...

@final
class GroupResult(tuple[Any, ...]):
    n_sequence_fields: ClassVar[int]
    n_fields: ClassVar[int]
    n_unnamed_fields: ClassVar[int]
    @property
    def gr_name(self) -> str: ...
    @property
    def gr_gid(self) -> int: ...
    @property
    def gr_mem(self) -> tuple[str, ...]: ...
    @property
    def source(self) -> NssSource: ...
    @property
    def local(self) -> bool: ...

@final
class NssPasswdIter(Iterator[PasswdResult], AbstractContextManager['NssPasswdIter']):
    def __next__(self) -> PasswdResult: ...
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: Any) -> bool: ...

@final
class NssGroupIter(Iterator[GroupResult], AbstractContextManager['NssGroupIter']):
    def __next__(self) -> GroupResult: ...
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: Any) -> bool: ...

def getpwnam(name: str, *, nss_module: str = ...) -> PasswdResult: ...
def getpwuid(uid: int, *, nss_module: str = ...) -> PasswdResult: ...
def iterpw(*, nss_module: str = ...) -> NssPasswdIter: ...
def getgrnam(name: str, *, nss_module: str = ...) -> GroupResult: ...
def getgrgid(gid: int, *, nss_module: str = ...) -> GroupResult: ...
def itergrp(*, nss_module: str = ...) -> NssGroupIter: ...
