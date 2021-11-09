## FwHunt IDA plugin

### Installation

Copy `fwhunt.py` and `fwhunt_ida` to IDA plugins directory

### Usage

* Analyze UEFI driver with [uefi_r2](https://github.com/binarly-io/uefi_r2)
    - example: `python3 /tmp/uefi_r2/uefi_r2_analyzer.py analyze-image DxeCore -o DxeCoreUefiR2.json`
* Open analyzed driver in IDA
* Open `Edit/Plugins/FwHunt` (at this step you will see `FwHunt rule generator` window):

    ![img1.png](rsrc/img1.png)

* Press the `Load` button to load the report generated in the first step
* Use the search box to find the protocols, GUIDs, PPIs, NVRAM variables you need
    - you can add them to the `FwHunt rule` by right-clicking:

        ![img2.png](rsrc/img2.png)

    - you can find them in the IDA database:

        ![img3.png](rsrc/img3.png)

* Use actions in IDA text view to add GUIDs, ascii strings, wide strings, hex strings, and code patterns:

    ![img4.png](rsrc/img4.png)

* `FwHunt rule preview` window will contain the current state of the rule:

    ![img5.png](rsrc/img5.png)

* Use `Reset` button to clear rule and `Save` button to dump rule in YAML file
