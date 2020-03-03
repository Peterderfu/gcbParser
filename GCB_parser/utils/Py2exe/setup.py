from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
buildOptions = dict(packages = [], excludes = [])

base = 'Console'

executables = [
    Executable('../../GCB_parser.py', base=base)
]

setup(name='a',
      version = '1.0',
      description = 'GCB檢測程式執行檔',
      options = dict(build_exe = buildOptions),
      executables = executables)
