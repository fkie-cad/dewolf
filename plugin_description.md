# dewolf

<img src="assets/logo.png" width="200">

dewolf is a research decompiler we developed during a research cooperation from 2019 to 2021 between Germany (Fraunhofer FKIE) and Singapore (DSO National Laboratories).

The restructuring of dewolf is based on the former DREAM/DREAM++ approach [Yakdan et al. NDSS 2015, IEEE (SP) 2016].

The decompiler dewolf is implemented as a plugin for Binary Ninja and uses their Medium-Level intermediate language as the starting point.
Although we consider dewolf to be pretty stable, it is still a research prototype and not extensively optimized for production use.
Consequently, you will likely observe a few bugs or even decompilation failures when applying dewolf on real-world binaries.

**If you encounter any bugs, please report them to us so that we can further improve dewolf. :)**

## Usage

After enabling the dewolf decompilation dock widget via **View > Other Docks > Show Dewolf**, the decompiled code for the currently active symbol will be displayed.
In the dewolf dock, it is possible to navigate through functions by double-clicking them.

![Widget Menu](https://user-images.githubusercontent.com/12004321/145460440-be4b7dfd-bf7e-497f-a7af-1911bf3efc50.png)

The automatic decompilation of selected functions can be toggled with the *follow* button.
Decompiled code is cached and can be generated again with the *decompile* button, e.g. after patching instructions in the binary view.

![Widget](https://user-images.githubusercontent.com/12004321/145460476-f869e5cc-d585-4f53-8920-6ecfa4b346d5.png)

## Configuration
dewolf has multiple configuration options of which some are configurable via the GUI.

You can configure dewolf from the Binary Ninja GUI by navigating to **Edit > Preferences > Settings** or by pressing <kbd>Ctrl</kbd> + <kbd>,</kbd>.
Search for **dewolf** in the search bar and all dewolf related settings will be displayed.

## Support

If you have any suggestions, or bug reports, please create an issue in the [Issue Tracker](https://github.com/fkie-cad/dewolf/issues).

In case you have any questions or other problems, feel free to send an email to:

[dewolf@fkie.fraunhofer.de](mailto:dewolf@fkie.fraunhofer.de).