import sys

from ryu.cmd import manager



def main():
    sys.argv.append("/home/hpdn/ryu-controller/mycontroller.py")
    sys.argv.append("--ofp-tcp-listen-port=6661")
    # sys.argv.append("--observe-links")
    sys.argv.append("--verbose")
    sys.argv.append("--enable-debugger")
    manager.main()

if __name__ == '__main__':
    main()