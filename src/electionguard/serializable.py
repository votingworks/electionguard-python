from base64 import b64encode, b64decode
from dataclasses import dataclass
from datetime import datetime
import re
from os import path
from typing import cast, Any, Type, TypeVar, Union, Final

from jsons import (
    dump,
    dumps,
    NoneType,
    load,
    loads,
    JsonsError,
    set_deserializer,
    set_serializer,
    set_validator,
    suppress_warnings,
    default_nonetype_deserializer,
)

S = TypeVar("S", bound="Serializable")
_T = TypeVar("_T")

JSON_FILE_EXTENSION: str = ".json"
WRITE: str = "w"
READ: str = "r"
JSON_PARSE_ERROR = '{"error": "Object could not be parsed due to json issue"}'
# TODO Issue #??: Jsons library incorrectly dumps class method
KEYS_TO_REMOVE = ["from_json", "from_json_file", "from_json_object"]


@dataclass
class Serializable:
    """
    Serializable class with methods to convert to json
    """

    def to_json(self, strip_privates: bool = True) -> str:
        """
        Serialize to json string
        :param strip_privates: strip private variables
        :return: the json string representation of this object
        """
        return write_json(self, strip_privates)

    def to_json_object(self, strip_privates: bool = True) -> Any:
        """
        Serialize to json object
        :param strip_privates: strip private variables
        :return: the json representation of this object
        """
        return write_json_object(self, strip_privates)

    def to_json_file(
        self, file_name: str, file_path: str = "", strip_privates: bool = True
    ) -> None:
        """
        Serialize an object to a json file
        :param file_name: File name
        :param file_path: File path
        :param strip_privates: Strip private variables
        """
        write_json_file(self, file_name, file_path, strip_privates)

    @classmethod
    def from_json(cls: Type[S], data: str) -> S:
        """
        Deserialize the provided data string into the specified instance
        :param data: JSON string
        """
        return read_json(data, cls)

    @classmethod
    def from_json_object(cls: Type[S], data: object) -> S:
        """
        Deserialize the provided data object into the specified instance
        :param data: JSON object
        """
        return read_json_object(data, cls)

    @classmethod
    def from_json_file(cls: Type[S], file_name: str, file_path: str = "") -> S:
        """
        Deserialize the provided file into the specified instance
        :param file_name: File name
        :param file_path: File path
        """
        return read_json_file(cls, file_name, file_path)


def _remove_key(obj: Any, key_to_remove: str) -> Any:
    """
    Remove key from object recursively
    :param obj: Any object
    :param key_to_remove: key to remove
    """
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if key == key_to_remove:
                del obj[key]
            else:
                _remove_key(obj[key], key_to_remove)
    elif isinstance(obj, list):
        for i in reversed(range(len(obj))):
            if obj[i] == key_to_remove:
                del obj[i]
            else:
                _remove_key(obj[i], key_to_remove)


def write_json(object_to_write: object, strip_privates: bool = True) -> str:
    """
    Serialize to json string
    :param object_to_write: object to write to json
    :param strip_privates: strip private variables
    :return: the json string representation of this object
    """
    set_serializers()
    suppress_warnings()
    try:
        json_object = write_json_object(object_to_write, strip_privates)
        json_string = cast(
            str,
            dumps(
                json_object,
                strip_privates=strip_privates,
                strip_nulls=True,
                ensure_ascii=False,
            ),
        )
        return json_string
    except JsonsError:
        return JSON_PARSE_ERROR


def write_json_object(object_to_write: object, strip_privates: bool = True) -> object:
    """
    Serialize to json object
    :param object_to_write: object to write to json
    :param strip_privates: strip private variables
    :return: the json representation of this object
    """
    set_serializers()
    suppress_warnings()
    try:
        json_object = dump(
            object_to_write,
            strip_privates=strip_privates,
            strip_nulls=True,
            ensure_ascii=False,
        )
        for key in KEYS_TO_REMOVE:
            _remove_key(json_object, key)
        return json_object
    except JsonsError:
        return JSON_PARSE_ERROR


def write_json_file(
    object_to_write: object,
    file_name: str,
    file_path: str = "",
    strip_privates: bool = True,
) -> None:
    """
    Serialize json data string to json file
    :param object_to_write: object to write to json
    :param file_name: File name
    :param file_path: File path
    :param strip_privates: strip private variables
    """
    json_file_path: str = path.join(file_path, file_name + JSON_FILE_EXTENSION)
    with open(json_file_path, WRITE) as json_file:
        json_file.write(write_json(object_to_write, strip_privates))


def read_json(data: Any, class_out: Type[_T]) -> _T:
    """
    Deserialize json file to object
    :param data: Json file data
    :param class_out: Object type
    :return: Deserialized object
    """
    set_deserializers()
    return cast(_T, loads(data, class_out))


def read_json_object(data: Any, class_out: Type[_T]) -> _T:
    """
    Deserialize json file to object
    :param data: Json file data
    :param class_out: Object type
    :return: Deserialized object
    """
    set_deserializers()
    return cast(_T, load(data, class_out))


def read_json_file(class_out: Type[_T], file_name: str, file_path: str = "") -> _T:
    """
    Deserialize json file to object
    :param class_out: Object type
    :param file_name: File name
    :param file_path: File path
    :return: Deserialized object
    """
    set_deserializers()
    json_file_path: str = path.join(file_path, file_name + JSON_FILE_EXTENSION)
    with open(json_file_path, READ) as json_file:
        data = json_file.read()
        target: _T = read_json(data, class_out)
    return target


ENCODE_THRESHOLD: Final[int] = 100_000_000


def int_to_maybe_base64(i: int) -> Union[str, int]:
    """
    Given a non-negative integer, returns a big-endian base64 encoding of the integer,
    if it's bigger than `ENCODE_THRESHOLD`, otherwise the input integer is returned.
    :param i: any non-negative integer
    :return: a string in base64 or just the input integer, if it's "small".
    """

    if i < 0:
        raise ValueError("int_to_maybe_base64 does not accept negative numbers")

    # Coercing mpz integers to vanilla integers, because we want consistent behavior.
    i = int(i)

    if i < ENCODE_THRESHOLD:
        return i

    # relevant discussion: https://stackoverflow.com/a/12859903/4048276
    b = i.to_bytes((i.bit_length() + 7) // 8, "big") or b"\0"
    return b64encode(b).decode("utf-8")


def maybe_base64_to_int(i: Union[str, int]) -> int:
    """
    Given a maybe-encoded big-endian base64 non-negative integer, or just a regular
    integer, such as might have been returned by `int_to_maybe_base64`, returns
    that integer, decoded.
    :param i: a base64-encoded integer, or just an integer
    :return: an integer
    """

    if isinstance(i, int):
        return i

    b = b64decode(i)
    return int.from_bytes(b, byteorder="big", signed=False)


def set_serializers() -> None:
    """Set serializers for jsons to use to cast specific classes"""

    # Local import to minimize jsons usage across files
    from .group import ElementModP, ElementModQ

    set_serializer(lambda p, **_: int_to_maybe_base64(p.to_int()), ElementModP)
    set_serializer(lambda q, **_: int_to_maybe_base64(q.to_int()), ElementModQ)
    set_serializer(lambda i, **_: int_to_maybe_base64(i), int)
    set_serializer(lambda dt, **_: dt.isoformat(), datetime)


def set_deserializers() -> None:
    """Set deserializers and validators for json to use to cast specific classes"""

    # Local import to minimize jsons usage across files
    from .group import ElementModP, ElementModQ, int_to_p_unchecked, int_to_q_unchecked

    set_deserializer(
        lambda p, cls, **_: int_to_p_unchecked(maybe_base64_to_int(p)), ElementModP
    )
    set_validator(lambda p: p.is_in_bounds(), ElementModP)

    set_deserializer(
        lambda q, cls, **_: int_to_q_unchecked(maybe_base64_to_int(q)), ElementModQ
    )
    set_validator(lambda q: q.is_in_bounds(), ElementModQ)

    set_deserializer(lambda i, cls, **_: maybe_base64_to_int(i), int)
    set_validator(lambda q: q.is_in_bounds(), ElementModQ)

    set_deserializer(
        lambda none, cls, **_: None
        if none == "None"
        else default_nonetype_deserializer(none),
        NoneType,
    )

    set_deserializer(lambda dt, cls, **_: _deserialize_datetime(dt), datetime)


def _deserialize_datetime(value: str) -> datetime:
    """
    The `fromisoformat` function doesn't recognize the Z (Zulu) suffix
    to indicate UTC.  For compatibility with more external clients, we
    should allow it.
    """
    tz_corrected = re.sub("Z$", "+00:00", value)
    return datetime.fromisoformat(tz_corrected)
