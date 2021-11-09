import binascii
import logging
import os
import uuid
from typing import List, Optional, Tuple

import ida_bytes
import ida_funcs
import idc

logger = logging.getLogger(__name__)


def get_guid_value(ea: int) -> Optional[str]:
    """
    Get the GUID value at a specific address

    @param: address

    @return: GUID value
    """

    guid = None

    if ida_funcs.get_func(ea) is not None:
        logger.info("Local GUIDs are not yet supported")
        # currently uefi_r2 does not support extracting local GUIDs
        # for this reason, there is no need to extract here either
        return None

    # extract GUID value
    try:
        data = ida_bytes.get_bytes(ea, 16)
        guid = str(uuid.UUID(bytes_le=data)).upper()
    except Exception as e:
        logger.error(f"Can't extract GUID value ({repr(e)})")

    return guid


def get_guid_name(ea: int) -> Optional[str]:
    """
    Get the GUID name

    @param ea: address

    @return: GUID name or None
    """

    name = idc.get_name(ea)

    if name is None:
        return name

    suf = "_GUID"
    index = name.find(suf)
    if index < 0:
        return name

    return name[: index + len(suf)]


def get_wide_string(ea: int) -> Optional[str]:
    """
    Get wide string located at specific address (max length: 512)

    @param ea: address

    @return: wide string or None
    """

    max_len = 512
    data = ida_bytes.get_bytes(ea, max_len * 2)

    if data is None:
        return None

    wide_end = data.find(b"\x00\x00")
    if wide_end < 0:
        wide_end = max_len * 2

    wide_string = data[: wide_end + 1]
    try:
        return wide_string.decode("utf-16le")
    except UnicodeDecodeError:
        return None


def get_ascii_string(ea: int) -> Optional[str]:
    """
    Get ascii string located at specific address (max length: 512)

    @param ea: address

    @return: ascii string or None
    """

    max_len = 512
    data = ida_bytes.get_bytes(ea, max_len)

    if data is None:
        return None

    ascii_end = data.find(b"\x00")
    if ascii_end < 0:
        ascii_end = max_len

    ascii_string = data[:ascii_end]
    try:
        return ascii_string.decode("utf-8")
    except UnicodeDecodeError:
        return None


def get_hex_string(start_ea: int, end_ea: int) -> Optional[str]:
    """
    Get hex string located at specific address (max length: 512)

    @param start_ea: start address
    @param end_ea: end address

    @return: hex string or None
    """

    max_len = 512

    data = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
    if data is None:
        return None

    data = data[:max_len]

    return binascii.hexlify(data).decode()


def get_code(start_ea: int, end_ea: int) -> Tuple[Optional[str], Optional[List[str]]]:
    """
    Get code from start_ea to end_ea

    @param start_ea: start address
    @param end_ea: end address

    @return: tuple(code, code_comment)
    """

    if ida_funcs.get_func(start_ea) is None or ida_funcs.get_func(end_ea) is None:
        return None, None

    data = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
    code = binascii.hexlify(data).decode()
    comments = list()

    # get comment
    ea = start_ea
    comments = list()
    while ea < end_ea:
        disasm_line = idc.generate_disasm_line(ea, 0)
        ea_next = idc.next_head(ea)
        opcodes = ida_bytes.get_bytes(ea, ea_next - ea)
        opcodes_hex = binascii.hexlify(opcodes).decode()
        opcodes_hex = opcodes_hex + " " * (32 - len(opcodes_hex))
        comments.append(f"# {opcodes_hex}    {disasm_line}")
        ea = ea_next

    return code, comments


def get_module_name() -> str:
    """
    Get module name

    @return: module name
    """

    idb_path = idc.get_idb_path()
    _, idb_name = os.path.split(idb_path)
    name, _ = os.path.splitext(idb_name)
    return name


def remove_addrs(items: list) -> list:
    """Remove address from each item
    (since the addresses may not coincide in the radare2/rizin and IDA)"""

    res = list()

    for item in items:
        if "address" in item:
            del item["address"]
        if item not in res:
            res.append(item)

    return res


def get_tree(data: dict) -> dict:
    """
    Handle data from uefi_r2 analysis report

    @param: data

    @return: tree
    """

    tree = dict()

    if "protocols" in data:
        tree["protocols"] = remove_addrs(data["protocols"])

    if "p_guids" in data:
        tree["p_guids"] = remove_addrs(data["p_guids"])

    if "ppi_list" in data:
        tree["ppi_list"] = remove_addrs(data["ppi_list"])

    if "nvram_vars" in data:
        tree["nvram_vars"] = remove_addrs(data["nvram_vars"])

    return tree
