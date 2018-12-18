import os
import pathlib
import shutil
import glob

ROOT = os.getcwd() + os.sep
BUILD_COMMAND = "pyinstaller --distpath {dp} --onefile {target}"
BIN_DIR = ROOT + "bin" + os.sep


def build_dropper():
    dropper_path = ROOT + "src" + os.sep + "dropper" + os.sep
    dropper_file = dropper_path + "dropper.py"

    build_cmd = "pyinstaller --distpath {dp} --onefile {target}".format(
        dp=BIN_DIR + "dropper", target=dropper_file
    )

    os.system(build_cmd)


def build_crypter():
    crypter_path = ROOT + "src" + os.sep + "crypter" + os.sep
    crypter_file = dropper_path + "crypter.py"

    build_cmd = "pyinstaller --distpath {dp} --onefile {target}".format(
        dp=BIN_DIR + "crypter", target=dropper_file
    )

    os.system(build_cmd)


def cleanup():
    [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]
    shutil.rmtree(ROOT + "build")
    for spec in glob.glob('*.spec', recursive=True):
        os.remove(spec)


def build_all():
    build_dropper()
    #build_crypter()
    cleanup()


if __name__ == "__main__":
    try:
        build_all()
    except KeyboardInterrupt:
        pass
