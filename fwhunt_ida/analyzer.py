import logging
import uuid
from typing import Optional

import ida_bytes
import ida_idaapi
import ida_segment

logger = logging.getLogger(__name__)


class Analyzer:
    """Analyzer class"""

    def __init__(self):
        pass

    @staticmethod
    def guid_bytes(guid: Optional[str]) -> Optional[bytes]:
        """Convert GUID structure to array of bytes"""

        if guid is None:
            return bytes()

        guid_bytes: bytes = bytes()

        try:
            guid_bytes = uuid.UUID(guid).bytes_le
        except ValueError as e:
            logger.error(repr(e))
            return None

        return guid_bytes

    @staticmethod
    def search_bytes(data: bytes) -> list:
        """
        Find data in IDB
        """

        res = list()

        seg = ida_segment.get_segm_by_name(".data")
        start_ea = seg.start_ea
        end_ea = seg.end_ea

        while True:
            ea = ida_bytes.bin_search(
                start_ea, end_ea, data, None, ida_bytes.BIN_SEARCH_FORWARD, 0
            )

            if ea == ida_idaapi.BADADDR:
                break

            res.append(ea)
            start_ea = ea + len(data)

        return res
