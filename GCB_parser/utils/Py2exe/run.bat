rm -rf build
python setup.py build
cd build
for /D %%D in ("exe*") do ren %%~D "GCB_parser"
cp "../../../arg.txt" GCB_parser
7z a -tzip GCB_parser.zip GCB_parser