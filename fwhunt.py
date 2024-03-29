import logging
import traceback
from typing import Any, Optional

import ida_idaapi
import ida_kernwin
import idc

from fwhunt import ui, utils

NAME = "FwHunt"
AUTHOR = "https://github.com/binarly-io/"

VERSION = "0.0.1"
DESCRIPTION = "Helper tool for generating FwHunt compliant rules"

g_form: Optional[ui.FwHuntForm] = None
g_rule: ui.FwHuntRule = ui.FwHuntRule()

logger = logging.getLogger(NAME)


# -----------------------------------------------------------------------
class FwHuntAction(ida_kernwin.action_handler_t):
    """Basic class for FwHunt action"""

    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def update(self, ctx) -> Any:
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(ctx.widget, None, self.name, "FwHunt/")
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


# -----------------------------------------------------------------------
class AddEfiGuid(FwHuntAction):

    name = "AddEfiGuid"
    description = "add GUID to detection rule"
    hotkey = str()

    def __init__(self) -> None:
        super().__init__()

    def activate(self, _ctx) -> bool:
        if g_rule.editor is None:
            return False

        ea = ida_kernwin.get_screen_ea()
        guid = utils.get_guid_value(ea)
        name = utils.get_guid_name(ea)

        logger.info(f"GUID: {guid} # {name}")

        if guid is None:
            return False

        # append GUID to rule
        g_rule.append_guid(guid, name)

        return True


# -----------------------------------------------------------------------
class AddAsciiString(FwHuntAction):

    name = "AddAsciiString"
    description = "add ascii string to detection rule"
    hotkey = str()

    def __init__(self) -> None:
        super().__init__()

    def activate(self, _ctx) -> bool:
        if g_rule.editor is None:
            return False

        ea = ida_kernwin.get_screen_ea()
        logger.info(f"Address: {ea:#x}")
        string = utils.get_ascii_string(ea)

        if string is None:
            return False

        # remove \n
        if "\n" in string:
            string = string.split("\n")[0]
        logger.info(f"String: {string}")

        if not len(string):
            return False

        # append ascii string to rule
        g_rule.append_string(string)

        return True


# -----------------------------------------------------------------------
class AddWideString(FwHuntAction):

    name = "AddWideString"
    description = "add wide string to detection rule"
    hotkey = str()

    def __init__(self) -> None:
        super().__init__()

    def activate(self, ctx) -> bool:
        if g_rule.editor is None:
            return False

        ea = ida_kernwin.get_screen_ea()
        logger.info(f"Address: {ea:#x}")
        string = utils.get_wide_string(ea)

        if string is None:
            return False

        # remove \n
        if "\n" in string:
            string = string.split("\n")[0]
        logger.info(f"Wide string: {string}")

        if not len(string):
            return False

        # append wide string to rule
        g_rule.append_wide_string(string)

        return True


# -----------------------------------------------------------------------
class AddHexString(FwHuntAction):

    name = "AddHexString"
    description = "add hex string to detection rule"
    hotkey = str()

    def __init__(self) -> None:
        super().__init__()

    def activate(self, _ctx) -> bool:
        if g_rule.editor is None:
            return False

        start_ea = idc.read_selection_start()
        end_ea = idc.read_selection_end()
        hex_string = utils.get_hex_string(start_ea, end_ea)

        logger.info(f"Hex string: {hex_string}")

        if hex_string is not None:
            # append hex string to rule
            g_rule.append_hex_string(hex_string)

        return True


# -----------------------------------------------------------------------
class AddCodeSnippet(FwHuntAction):

    name = "AddCodeSnippet"
    description = "add code to detection rule"
    hotkey = str()

    def __init__(self) -> None:
        super().__init__()

    def activate(self, _ctx) -> bool:
        if g_rule.editor is None:
            return False

        start_ea = idc.read_selection_start()
        end_ea = idc.read_selection_end()

        # if selected only one line
        if start_ea == idc.BADADDR and end_ea == idc.BADADDR:
            start_ea = ida_kernwin.get_screen_ea()
            end_ea = idc.next_head(start_ea)

        logger.info(f"Start code address: {start_ea:#x}")
        logger.info(f"End code address: {end_ea:#x}")
        code, comments = utils.get_code(start_ea, end_ea)
        logger.info(f"Code: {code}")

        if code is not None:
            # append hex string to rule
            g_rule.append_code(code, comments)

        return True


# -----------------------------------------------------------------------
class FwHuntHelper(ida_idaapi.plugin_t):
    """FwHunt helper class"""

    flags = 0
    comment = DESCRIPTION
    help = DESCRIPTION
    wanted_name = NAME
    wanted_hotkey = str()

    @staticmethod
    def register_action(action, *args) -> None:
        desc = ida_kernwin.action_desc_t(
            action.name, action.description, action(*args), action.hotkey
        )
        ida_kernwin.register_action(desc)

    @staticmethod
    def init() -> Any:
        ida_kernwin.msg(f"\n{NAME} ({VERSION})\n")

        return ida_idaapi.PLUGIN_KEEP

    @staticmethod
    def run(_arg) -> bool:
        global g_form

        if g_form is not None:
            g_form.Close(options=0)

        # initialize the form
        g_form = ui.FwHuntForm()
        g_form.Show("FwHunt rule generator")
        g_rule.install_editor(g_form.rule_preview)
        g_form.fwhunt_scan_info.install_rule(g_rule)

        # add actions
        FwHuntHelper.register_action(AddEfiGuid)
        FwHuntHelper.register_action(AddAsciiString)
        FwHuntHelper.register_action(AddWideString)
        FwHuntHelper.register_action(AddHexString)
        FwHuntHelper.register_action(AddCodeSnippet)

    @staticmethod
    def term() -> None:
        ida_kernwin.unregister_action(AddEfiGuid.name)
        ida_kernwin.unregister_action(AddAsciiString.name)
        ida_kernwin.unregister_action(AddWideString.name)
        ida_kernwin.unregister_action(AddHexString.name)
        ida_kernwin.unregister_action(AddCodeSnippet.name)


# -----------------------------------------------------------------------
# Entry for plugin
def PLUGIN_ENTRY() -> Optional[FwHuntHelper]:
    try:
        return FwHuntHelper()
    except Exception as e:
        logger.error(f"{str(e)}\n{traceback.format_exc()}")
    return None


# -----------------------------------------------------------------------
# Entry for IDAPyhton script
def main() -> None:
    try:
        FwHuntHelper.init()
        FwHuntHelper.run(0)
    except Exception as e:
        logger.error(f"{str(e)}\n{traceback.format_exc()}")


if __name__ == "__main__":
    main()
