import PataponDebugger
import PPSSPPDebugger


def test_patapon_debugger():
    test = PataponDebugger.PataponDebugger()
    path = r"c:\Users\Nikolaos\D\Tools\Patapon\Tools\PacViewer\PacViewer 3.0.12\p3_instruction_set_with_addresses.bin"
    try:
        test.read_instruction_set(path)
        pass
    except Exception as e:
        print("read_instruction_set error!")
        print(e)
