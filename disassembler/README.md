# arm64_disassembler

### Testing

use `make unittest` to compile ./unittest/arm64dis.so

within ./unittest, run `./unitTest.py -vv -u ./allInstruction.txt` which uses capstone as an oracle for comparison

within ./unittest, run `./test_absolute.py mteInstruction.txt` which compares against the expected text result in the .txt file

