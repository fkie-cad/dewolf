<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>

# dewolf

<img src="assets/logo.png" width="200">

dewolf is a research decompiler we developed during a research cooperation from 2019 to 2021 between Germany (Fraunhofer FKIE) and Singapore (DSO National Laboratories).

The restructuring of dewolf is based on the former DREAM/DREAM++ approach [Yakdan et al. NDSS 2015, IEEE (SP) 2016].

The decompiler dewolf is implemented as a plugin for Binary Ninja and uses their Medium-Level intermediate language as the starting point.
Although we consider dewolf to be pretty stable, it is still a research prototype and not extensively optimized for production use.
Consequently, you will likely observe a few bugs or even decompilation failures when applying dewolf on real-world binaries.

**If you encounter any bugs, please report them to us so that we can further improve dewolf. :)**

___
## Installation

### Dependencies
Before we start, please make sure you have the following dependencies installed and available on your computer:

- At least [Python 3.8](https://www.python.org/)
- Latest stable release of [Binary Ninja (>=2.4)](https://binary.ninja/)
- [astyle](https://code.tools/man/1/astyle/) for proper indentation of the decompiled code
- [libgraph-easy-perl](https://packages.ubuntu.com/source/focal/libgraph-easy-perl) only required for printing ASCII graphs

Under **Linux** (Ubuntu / Debian), you can use the following command to install both **astyle** and **libgraph-easy-perl**:

```bash
sudo apt install astyle libgraph-easy-perl
```
Under **Windows**, please make sure the **astyle**-binary has been added to the environment Path.

### Binary Ninja Plugin
Follow the steps below to setup dewolf as a GUI plugin for Binary Ninja.
Afterwards, you will be able to inspect decompiled code from a Binary Ninja dock.

#### Step 1: 
Clone the dewolf repository into the Binary Ninja plugin folder which is located in one of the following paths corresponding to your operating system:

**Linux:** `\path{~/.binaryninja/plugins}`  
**MacOS:** `\path{~/Library/Application Support/Binary Ninja}`  
**Windows:** `%APPDATA%\Binary Ninja`  

**Attention:**
If you want to use a python virtual environment, make sure it is enabled for the next steps and also when starting Binary Ninja.

#### Step 2: 
Install dewolf's python dependencies with:

```bash
pip install -r requirements.txt
```

#### Step 3: 
Install Binary Ninja python API with:

```bash
python <binaryninja_path>/scripts/install_api.py [-v if using virtualenv]
```

**Warning:** Changes made to the dewolf plugin only comes into effect after restarting the Binary Ninja GUI.


___
## Usage

The dewolf decompiler can be used from both the command line and within Binary Ninja. 

### GUI
AAfter enabling the dewolf decompilation dock widget via **View > Other Docks > Show Dewolf**, the decompiled code for the currently active symbol will be displayed.
In the dewolf dock, it is possible to navigate through functions by double-clicking them.

![Widget Menu](https://user-images.githubusercontent.com/12004321/145460440-be4b7dfd-bf7e-497f-a7af-1911bf3efc50.png)

The automatic decompilation of selected functions can be toggled with the *follow* button.
Decompiled code is cached and can be generated again with the *decompile* button, e.g. after patching instructions in the binary view.

![Widget](https://user-images.githubusercontent.com/12004321/145460476-f869e5cc-d585-4f53-8920-6ecfa4b346d5.png)

### CLI
For batch decompilation, it may be more convenient to utilize dewolf as a command line program.
If you would like to use dewolf from the command line, you can invoke decompilation of an entire binary with the following command:

```bash
python decompile.py <path/to/binary>
```

If you wish to decompile a specific function, the function name can be provided as the second parameter:

```bash
python decompile.py <path/to/binary> <function_name>
```

By default, the generated code is displayed on the console.
If you want to write the output to a file instead, you can specify it with the `--output/-o` flag.
Please use the `--help` flag for more information.

___
## Configuration
dewolf has multiple configuration options of which some are configurable via the GUI. 

### via GUI
You can configure dewolf from the Binary Ninja GUI by navigating to **Edit > Preferences > Settings** or by pressing **\ctrl** + **,** .
Search for **dewolf** in the search bar and all dewolf related settings will be displayed.

**Warning:** Configurations made through Binary Ninja will not be taken into account when dewolf is started via command line interface. To configure dewolf when started via CLI, do as described in the following section.

### via CLI
To apply settings for command line mode or using advanced settings not shown in the GUI, you can provide a *config.json* file in the decompiler root folder.
The format of such a config file has to be as follows:

```
{
  "section.key": value,
  "expression-propagation.maximum_instruction_complexity": 5
}
```
All available settings can be found in `dewolf/util/default.json`.

___
## Support

If you have any suggestions, or bug reports, please create an issue in the Issue Tracker.

In case you have any questions or other problems, feel free to send an email to:

[dewolf@fkie.fraunhofer.de](mailto:dewolf@fkie.fraunhofer.de).
