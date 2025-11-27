## Guide: Running `cabal test simulation` with Python Reference Comparisons

This setup has been tested on **Windows using WSL2**, because `slh-dsa` is not included in the standard Debian repositories. Using a Python virtual environment is recommended.

### Steps

1. **Install `virtualenv`** (if not already installed):

```bash
sudo apt install python3-virtualenv
``` 
2. **Create a virtual environment:**
```bash
virtualenv -p python3 test
``` 
3. **Check the location of `virtualenv`:**
```bash
which virtualenv
``` 
4. **Activate the virtual environment:**
```bash
source test/bin/activate
``` 
5. **Install the Python library `slh-dsa`:**
```bash
pip3 install slh-dsa
``` 
5. **Install the Python library `pandas`:** This is for the constant cycle test
```bash
pip3 install pandas
``` 
6. **Using this Python environment inside a Nix shell:**
    1. First, enter the Nix environment:`nix develop`

    2. Then activate the Python virtual environment: `source test/bin/activate`

Now you can run `cabal test simulation` and it will use the Python reference implementation correctly.