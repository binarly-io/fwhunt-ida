import json
import logging
from typing import Dict, List, Optional, Tuple

import ida_kernwin
from PyQt5 import QtCore, QtGui, QtWidgets

from .analyzer import Analyzer
from .utils import get_module_name, get_tree

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------
class FwHuntRule:
    """FwHunt rule class"""

    def __init__(self) -> None:
        self.editor: Optional[FwHuntRulePreview] = None

        # from IDA
        self._guids: List[Tuple[str, Optional[str]]] = list()
        self._code: List[Tuple[str, Optional[List[str]]]] = list()
        self._strings: List[str] = list()
        self._wide_strings: List[str] = list()
        self._hex_strings: List[str] = list()

        # from fwhunt-scan (guids already exist)
        self._protocols: List[Dict] = list()
        self._ppi_list: List[Dict] = list()
        self._nvram_vars: List[Dict] = list()

    def install_editor(self, editor):
        # FwHuntRulePreview class object
        # with set_text method
        self.editor = editor

    def append_protocol(self, protocol) -> None:
        logger.info(protocol)
        if protocol not in self._protocols:
            self._protocols.append(protocol)
            current_rule = self.generate_rule()
            self.editor.set_text(current_rule)

    def append_nvram_var(self, nvram_var) -> None:
        logger.info(nvram_var)
        if nvram_var not in self._nvram_vars:
            self._nvram_vars.append(nvram_var)
            current_rule = self.generate_rule()
            self.editor.set_text(current_rule)

    def append_ppi(self, ppi) -> None:
        logger.info(ppi)
        if ppi not in self._ppi_list:
            self._ppi_list.append(ppi)
            current_rule = self.generate_rule()
            self.editor.set_text(current_rule)

    def append_guid(self, guid_value: str, guid_name: Optional[str]) -> None:
        if (guid_value, guid_name) not in self._guids:
            self._guids.append((guid_value, guid_name))
            current_rule = self.generate_rule()
            self.editor.set_text(current_rule)

    def append_code(self, hex_string: str, code_comments: Optional[List[str]]) -> None:
        if (hex_string, code_comments) not in self._code:
            self._code.append((hex_string, code_comments))
            current_rule = self.generate_rule()
            self.editor.set_text(current_rule)

    def append_string(self, string: str) -> None:
        if string not in self._strings:
            self._strings.append(string)
            current_rule = self.generate_rule()
            self.editor.set_text(current_rule)

    def append_wide_string(self, wide_string: str) -> None:
        if wide_string not in self._wide_strings:
            self._wide_strings.append(wide_string)
            current_rule = self.generate_rule()
            self.editor.set_text(current_rule)

    def append_hex_string(self, hex_string: str) -> None:
        if hex_string not in self._hex_strings:
            self._hex_strings.append(hex_string)
            current_rule = self.generate_rule()
            self.editor.set_text(current_rule)

    def clear(self) -> None:
        self._guids = list()
        self._code = list()
        self._strings = list()
        self._wide_strings = list()
        self._hex_strings = list()
        self._protocols = list()
        self._ppi_list = list()
        self._nvram_vars = list()

        current_rule = self.generate_rule()
        self.editor.set_text(current_rule)

    def is_empty(self) -> bool:
        for item in [
            self._guids,
            self._code,
            self._strings,
            self._wide_strings,
            self._hex_strings,
            self._protocols,
            self._ppi_list,
            self._nvram_vars,
        ]:
            if len(item) > 0:
                return False
        return True

    def _get_rule_content(self) -> str:
        rule_content: str = str()

        # set rule name
        rule_name = get_module_name()
        rule_content = f"{rule_content}{rule_name}:\n"

        # set meta
        rule_content = f"{rule_content}  meta:\n"
        rule_content = f"{rule_content}    author: ...\n"
        rule_content = f"{rule_content}    name: {rule_name}\n"
        rule_content = f"{rule_content}    namespace: fwhunt-ida\n"
        rule_content = f"{rule_content}    description: ...\n"
        rule_content = f"{rule_content}    volume guids:\n"
        rule_content = f"{rule_content}      - ...\n"

        # set GUIDs
        if len(self._guids) > 0:
            rule_content = f"{rule_content}  guids:\n"
            rule_content = f"{rule_content}    and:\n"
            for (guid, guid_name) in self._guids:
                rule_content = f"{rule_content}      - name: {guid_name}\n"
                rule_content = f"{rule_content}        value: {guid}\n"

        # set protocols
        if len(self._protocols) > 0:
            rule_content = f"{rule_content}  protocols:\n"
            rule_content = f"{rule_content}    and:\n"
            for protocol in self._protocols:
                name = protocol["name"]
                value = protocol["value"]
                service = protocol["service"]
                rule_content = f"{rule_content}      - name: {name}\n"
                rule_content = f"{rule_content}        value: {value}\n"
                rule_content = f"{rule_content}        service:\n"
                rule_content = f"{rule_content}          name: {service}\n"

        # set ppi
        if len(self._ppi_list) > 0:
            rule_content = f"{rule_content}  ppi:\n"
            rule_content = f"{rule_content}    and:\n"
            for ppi in self._ppi_list:
                name = ppi["name"]
                value = ppi["value"]
                service = ppi["service"]
                rule_content = f"{rule_content}      - name: {name}\n"
                rule_content = f"{rule_content}        value: {value}\n"
                rule_content = f"{rule_content}        service:\n"
                rule_content = f"{rule_content}          name: {service}\n"

        # set nvram
        if len(self._nvram_vars) > 0:
            rule_content = f"{rule_content}  nvram:\n"
            rule_content = f"{rule_content}    and:\n"
            for nvram_var in self._nvram_vars:
                name = nvram_var["name"]
                guid = nvram_var["guid"]
                service = nvram_var["service"]["name"]
                rule_content = f"{rule_content}      - name: {name}\n"
                rule_content = f"{rule_content}        guid: {guid}\n"
                rule_content = f"{rule_content}        service:\n"
                rule_content = f"{rule_content}          name: {service}\n"

        # set ascii strings
        if len(self._strings) > 0:
            rule_content = f"{rule_content}  strings:\n"
            rule_content = f"{rule_content}    and:\n"
            for string in self._strings:
                rule_content = f"{rule_content}    - {string}\n"

        # set wide strings
        if len(self._wide_strings) > 0:
            rule_content = f"{rule_content}  wide_strings:\n"
            rule_content = f"{rule_content}    and:\n"
            for wide_string in self._wide_strings:
                rule_content = f"{rule_content}      - utf16le: {wide_string}\n"

        # set hex strings
        if len(self._hex_strings) > 0 or len(self._code) > 0:
            rule_content = f"{rule_content}  hex_strings:\n"
            rule_content = f"{rule_content}    and:\n"
            for hex_string in self._hex_strings:
                rule_content = f"{rule_content}      - {hex_string}\n"

            for (hex_string, code_comments) in self._code:
                rule_content = f"{rule_content}      - {hex_string}\n"
                for comment in code_comments:
                    rule_content = f"{rule_content}          {comment}\n"

        return rule_content

    def generate_rule(self) -> str:
        rule: str = self._get_rule_content()

        return rule


# -----------------------------------------------------------------------
# Some things are borrowed from capa IDA plugin
# (https://github.com/fireeye/capa/tree/master/capa/ida/plugin)
# since the goals in the UI are similar
class UefiR2Info(QtWidgets.QTreeWidget):

    MAX_SECTION_SIZE = 750

    def __init__(self, parent=None):
        super(UefiR2Info, self).__init__(parent)

        self.rule: FwHuntRule = None

        self.setHeaderLabels(["Item", "Description"])
        self.header_font = None
        self._load_header_font()
        self.header().setFont(self.header_font)
        self.setStyleSheet(
            "QTreeView::item {padding-right: 15 px;padding-bottom: 2 px;}"
        )

        # Configure view columns to auto-resize
        for idx in range(2):
            self.header().setSectionResizeMode(idx, QtWidgets.QHeaderView.Interactive)

        self.setExpandsOnDoubleClick(False)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

        # Connect slots
        self.itemDoubleClicked.connect(self.slot_item_double_clicked)
        self.customContextMenuRequested.connect(self.slot_custom_context_menu_requested)
        self.expanded.connect(self.slot_resize_columns_to_content)
        self.collapsed.connect(self.slot_resize_columns_to_content)

        # Font
        self.item_font = None
        self._load_item_font()

        # Data loaded from JSON
        self.tree: dict = None

        self.reset_view()

    def install_rule(self, rule):
        self.rule = rule

    def resize_columns_to_content(self):
        self.header().resizeSections(QtWidgets.QHeaderView.ResizeToContents)
        if self.header().sectionSize(0) > UefiR2Info.MAX_SECTION_SIZE:
            self.header().resizeSection(0, UefiR2Info.MAX_SECTION_SIZE)

    def slot_item_double_clicked(self) -> bool:
        """Hanlder for item double clicked action"""

        logger.info("Item double clicked")

        # get data
        data = self.selectedItems()[0].data(0, 0x100)
        if data is None:
            return False

        logger.info(data)

        return True

    def slot_menu_rule(self, action) -> bool:
        """Menu handler (add to rule)"""

        text = action.text()
        logger.info(f"Menu handler ({text})")

        # get data
        data = self.selectedItems()[0].data(0, 0x100)
        if data is None:
            return False

        if "guid" in data:
            guid = data["guid"]
            self.rule.append_guid(guid["value"], guid["name"])
            return True

        if "protocol" in data:
            protocol = data["protocol"]
            self.rule.append_protocol(protocol)
            return True

        if "ppi" in data:
            ppi = data["ppi"]
            self.rule.append_ppi(ppi)
            return True

        if "nvram_var" in data:
            nvram_var = data["nvram_var"]
            self.rule.append_nvram_var(nvram_var)
            return True

        return True

    def slot_menu_jmp(self, action) -> bool:
        """Menu handler (jump to)"""

        text = action.text()
        logger.info(f"Menu handler ({text})")

        try:
            addr = int(text.split()[-1], 16)
            ida_kernwin.jumpto(addr)
        except Exception as e:
            logger.error(repr(e))
            return False

        return True

    def build_action(self, o, display, data, slot):
        action = QtWidgets.QAction(display, o)

        action.setData(data)
        action.triggered.connect(lambda checked: slot(action))

        return action

    def build_context_menu(self, o, actions):
        menu = QtWidgets.QMenu()

        for action in actions:
            if isinstance(action, QtWidgets.QMenu):
                menu.addMenu(action)
            else:
                menu.addAction(self.build_action(o, *action))

        return menu

    def build_context_menu_jmps(self, data, pos) -> bool:
        """Build context menu for jumps"""

        gb = None
        if "child_guid" in data:
            gb = Analyzer.guid_bytes(data["child_guid"])

        elif "child_value" in data:
            gb = Analyzer.guid_bytes(data["child_value"])

        elif "child_service" in data:
            return True

        elif "child_name" in data:
            return True

        if gb is not None:
            addrs = Analyzer.search_bytes(gb)
            actions = list()
            for addr in addrs:
                actions.append((f"Jmp to {addr:#x}", (), self.slot_menu_jmp))
            menu_jmp = self.build_context_menu(self.parent(), actions)
            menu_jmp.exec_(self.viewport().mapToGlobal(pos))
            return True

        return False

    def slot_custom_context_menu_requested(self, pos) -> bool:
        """Handler for custom context menu requested action"""

        logger.info("Custom context menu requested")

        if len(self.selectedItems()) != 1:
            return False

        # if we can get data from this node
        data = self.selectedItems()[0].data(0, 0x100)
        if data is None:
            return False

        logger.info(f"data: {json.dumps(data)}")

        # build context menu for jumps
        if self.build_context_menu_jmps(data, pos):
            return True

        # build context menu for rule
        actions = list()
        actions.append(("Add to rule", (), self.slot_menu_rule))

        menu_rule = self.build_context_menu(self.parent(), actions)
        menu_rule.exec_(self.viewport().mapToGlobal(pos))

        return True

    def slot_resize_columns_to_content(self):
        """Handler for resize columns to content action"""

        logger.info("Resize columns to content")
        self.resize_columns_to_content()

    def _load_header_font(self):
        self.header_font = QtGui.QFont("Courier")
        self.header_font.setBold(True)
        self.header_font.setPointSize(13)

    def _load_item_font(self):
        self.item_font = QtGui.QFont("Courier")
        self.item_font.setPointSize(13)

    def _add_item(self, name, value, parent):
        item = QtWidgets.QTreeWidgetItem(parent)
        item.setText(0, f"{name}: {value}")
        item.setFont(0, self.item_font)
        item.setData(
            0, 0x100, {f"child_{name}": value}
        )  # add child_ prefix to distinguish from parent data

    def _load_ppi_list(self, info):
        parent_item = QtWidgets.QTreeWidgetItem()
        parent_item.setText(0, "ppi_list")
        parent_item.setText(1, "List of PPI")
        for column in [0, 1]:
            parent_item.setFont(column, self.item_font)
        self.addTopLevelItem(parent_item)

        for i, element in enumerate(info):
            child_item = QtWidgets.QTreeWidgetItem(parent_item)
            child_item.setText(0, f"{i:#d}")
            child_item.setFont(0, self.item_font)

            # in order to receive this data
            # in slot_custom_context_menu_requested
            data = {"ppi": element}
            child_item.setData(0, 0x100, data)

            self._add_item("name", element["name"], child_item)
            self._add_item("value", element["value"], child_item)
            self._add_item("service", element["service"], child_item)

    def _load_guids(self, info):
        parent_item = QtWidgets.QTreeWidgetItem()
        parent_item.setText(0, "guids")
        parent_item.setText(1, "List of GUIDs")
        for column in [0, 1]:
            parent_item.setFont(column, self.item_font)
        self.addTopLevelItem(parent_item)

        for i, element in enumerate(info):
            child_item = QtWidgets.QTreeWidgetItem(parent_item)
            child_item.setText(0, f"{i:#d}")
            child_item.setFont(0, self.item_font)

            # in order to receive this data
            # in slot_custom_context_menu_requested
            data = {"guid": element}
            child_item.setData(0, 0x100, data)

            self._add_item("name", element["name"], child_item)
            self._add_item("value", element["value"], child_item)

    def _load_protocols(self, info):
        parent_item = QtWidgets.QTreeWidgetItem()
        parent_item.setText(0, "protocols")
        parent_item.setText(1, "List of protocols")
        for column in [0, 1]:
            parent_item.setFont(column, self.item_font)
        self.addTopLevelItem(parent_item)

        for i, element in enumerate(info):
            child_item = QtWidgets.QTreeWidgetItem(parent_item)
            child_item.setText(0, f"{i:#d}")
            child_item.setFont(0, self.item_font)

            # in order to receive this data
            # in slot_custom_context_menu_requested
            data = {"protocol": element}
            child_item.setData(0, 0x100, data)

            self._add_item("name", element["name"], child_item)
            self._add_item("value", element["value"], child_item)
            self._add_item("service", element["service"], child_item)

    def _load_nvram_vars(self, info):
        parent_item = QtWidgets.QTreeWidgetItem()
        parent_item.setText(0, "nvram_vars")
        parent_item.setText(1, "List of NVRAM variables")
        for column in [0, 1]:
            parent_item.setFont(column, self.item_font)
        self.addTopLevelItem(parent_item)

        for i, element in enumerate(info):
            child_item = QtWidgets.QTreeWidgetItem(parent_item)
            child_item.setText(0, f"{i:#d}")
            child_item.setFont(0, self.item_font)

            # in order to receive this data
            # in slot_custom_context_menu_requested
            data = {"nvram_var": element}
            child_item.setData(0, 0x100, data)

            self._add_item("name", element["name"], child_item)
            self._add_item("guid", element["guid"], child_item)
            self._add_item("service", element["service"]["name"], child_item)

    def _load_tree(self, tree: dict):

        # need to handle each type of data separately
        if "ppi_list" in tree and len(tree["ppi_list"]) > 0:
            self._load_ppi_list(tree["ppi_list"])

        if "p_guids" in tree and len(tree["p_guids"]) > 0:
            self._load_guids(tree["p_guids"])

        if "protocols" in tree and len(tree["protocols"]) > 0:
            self._load_protocols(tree["protocols"])

        if "nvram_vars" in tree and len(tree["nvram_vars"]) > 0:
            self._load_nvram_vars(tree["nvram_vars"])

    def update_search(self, search_data: list):
        """Update tree content (with new data from search query)"""

        self.reset_view()

        tree = dict(
            {
                "ppi_list": list(),
                "p_guids": list(),
                "protocols": list(),
                "nvram_vars": list(),
            }
        )

        # generate tree right format
        # (to avoid this we need to change the format in the
        # uefi_f2 analysis report)
        for data in search_data:

            if "guid" in data:
                if data["guid"] not in tree["p_guids"]:
                    tree["p_guids"].append(data["guid"])
                continue

            if "protocol" in data:
                if data["protocol"] not in tree["protocols"]:
                    tree["protocols"].append(data["protocol"])
                continue

            if "ppi" in data:
                if data["ppi"] not in tree["ppi_list"]:
                    tree["ppi_list"].append(data["ppi"])
                continue

            if "nvram_var" in data:
                if data["nvram_var"] not in tree["nvram_vars"]:
                    tree["nvram_vars"].append(data["nvram_var"])
                continue

        self._load_tree(tree)

    def update_tree(self):
        """Update tree content (with new data from fwhunt-scan analysis result)"""

        self.reset_view()
        self._load_tree(self.tree)

    def reset_view(self):
        self.clear()


# -----------------------------------------------------------------------
class FwHuntRulePreview(QtWidgets.QTextEdit):
    def __init__(self, parent=None):
        super(FwHuntRulePreview, self).__init__(parent)

        self.setFont(QtGui.QFont("Courier", weight=QtGui.QFont.Bold))
        self.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.setStyleSheet("border: 2px solid grey")

    def reset_view(self):
        self.clear()

    def set_text(self, text):
        self.setText(text)


# -----------------------------------------------------------------------
class FwHuntForm(ida_kernwin.PluginForm):
    """Main form for FwHunt rule"""

    def __init__(self):
        super(FwHuntForm, self).__init__()

        # Tree and editor
        self.rule_preview: FwHuntRulePreview = None
        self.fwhunt_scan_info: UefiR2Info = None
        self._main_elements = None  # QtWidgets.QHBoxLayout

        # Labels font
        self.font = None  # QtGui.QFont

        # Labels
        self.label_info = None  # QtWidgets.QLabel
        self.label_preview = None  # QtWidgets.QLabel

        # Search box
        self.search = None  # QtWidgets.QLineEdit

        # Buttons
        self.button_load = None  # QtWidgets.QPushButton
        self.button_reset = None  # QtWidgets.QPushButton
        self.button_save = None  # QtWidgets.QPushButton
        self.buttons = None  # QtWidgets.QHBoxLayout

        # GUIDs addresses (for jumps)
        self.guids: dict = Optional[Dict[str, int]]

    def OnCreate(self, form):
        """Called when the widget is created"""

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)

        # Init tree and editor
        self.rule_preview = FwHuntRulePreview(parent=self.parent)
        self.fwhunt_scan_info = UefiR2Info(parent=self.parent)

        # Add all elements to form
        self._load_buttons()
        self._load_font()
        self._load_label_preview()
        self._load_label_info()
        self._load_search()
        self._load_main_elements()
        self._load_parent()

    def ask_json_file(self):
        return QtWidgets.QFileDialog.getSaveFileName(
            None, "Select JSON file with fwhunt-scan analysis result", "", "*.json"
        )[0]

    def ask_yml_file(self):
        return QtWidgets.QFileDialog.getSaveFileName(
            None, "Select a location to save FwHunt rule file", "", "*.yml"
        )[0]

    def slot_load(self) -> bool:
        """Load button handler"""

        logger.info("Load button handler")

        fwhunt_scan_analysis = ida_kernwin.ask_file(0, "*.json", "fwhunt-scan analysis")

        if not fwhunt_scan_analysis:
            logger.error("No file chosen")
            return False

        data = None

        try:
            with open(fwhunt_scan_analysis, "r") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(repr(e))

        if data is None:
            return False

        logger.info(json.dumps(data, indent=2))

        tree = get_tree(data)

        logger.info(json.dumps(tree, indent=2))

        self.fwhunt_scan_info.tree = tree
        self.fwhunt_scan_info.update_tree()

        return True

    def slot_reset(self):
        """Reset button handler"""

        logger.info("Reset button handler")
        self.fwhunt_scan_info.rule.clear()

    def slot_save(self) -> bool:
        """Save button handler"""

        if self.fwhunt_scan_info.rule.is_empty():
            ida_kernwin.info("FwHunt rule is empty")
            return False

        rule_path = self.ask_yml_file()
        logger.info(f"Rule path: {rule_path}")

        if not rule_path:
            return False

        current_rule = self.fwhunt_scan_info.rule.generate_rule()
        with open(rule_path, "w") as f:
            f.write(current_rule)

        return True

    def slot_search(self, text) -> bool:
        """Search query handler"""

        # set original data (fwhunt_scan_info.tree)
        self.fwhunt_scan_info.update_tree()

        # find elements by search query
        elements = self.fwhunt_scan_info.findItems(
            text,
            QtCore.Qt.MatchContains | QtCore.Qt.MatchRecursive,
            column=0,
        )

        # generate data by search query
        search_data = list()
        for element in elements:
            if element.parent() is None:
                continue
            data = element.parent().data(0, 0x100)
            if data is None:
                continue
            search_data.append(data)

        self.fwhunt_scan_info.update_search(search_data)

        return True

    def _load_search(self):
        line = QtWidgets.QLineEdit()
        line.setPlaceholderText("search...")
        line.textChanged.connect(self.slot_search)

        self.search = line

    def _load_buttons(self):
        load_button = QtWidgets.QPushButton("Load")
        reset_button = QtWidgets.QPushButton("Reset")
        analyze_button = QtWidgets.QPushButton("Analyze")
        save_button = QtWidgets.QPushButton("Save")

        load_button.clicked.connect(self.slot_load)
        reset_button.clicked.connect(self.slot_reset)
        save_button.clicked.connect(self.slot_save)

        layout = QtWidgets.QHBoxLayout()
        layout.addWidget(load_button)
        layout.addWidget(reset_button)
        layout.addStretch(2)
        layout.addWidget(save_button, alignment=QtCore.Qt.AlignRight)

        self.button_load = load_button
        self.button_reset = reset_button
        self.button_save = save_button
        self.buttons = layout

    def _load_font(self):
        self.font = QtGui.QFont()
        self.font.setBold(True)
        self.font.setPointSize(12)

    def _load_label_preview(self):
        self.label_preview = QtWidgets.QLabel()
        self.label_preview.setAlignment(QtCore.Qt.AlignCenter)
        self.label_preview.setText("FwHunt rule preview")
        self.label_preview.setFont(self.font)

    def _load_label_info(self):
        self.label_info = QtWidgets.QLabel()
        self.label_info.setAlignment(QtCore.Qt.AlignCenter)
        self.label_info.setText("fwhunt-scan analysis result")
        self.label_info.setFont(self.font)

    def _load_main_elements(self):
        layout = QtWidgets.QHBoxLayout()

        splitter_preview = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        layout_preview = QtWidgets.QHBoxLayout()
        layout_preview.addWidget(self.rule_preview)
        splitter_preview.addWidget(self.label_preview)
        splitter_preview.setLayout(layout_preview)

        splitter_info = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        layout_info = QtWidgets.QHBoxLayout()
        layout_info.addWidget(self.search)
        layout_info.addWidget(self.fwhunt_scan_info)
        splitter_info.addWidget(self.label_info)
        splitter_info.setLayout(layout_info)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.addWidget(splitter_info)
        splitter.addWidget(splitter_preview)

        layout.addWidget(splitter)

        self.main_elements = layout

    def _load_parent(self):
        layout = QtWidgets.QVBoxLayout()

        layout.addLayout(self.main_elements)
        layout.addLayout(self.buttons)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        """Called when the widget is closed"""
        pass
