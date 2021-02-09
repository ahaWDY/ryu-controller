cd /home/hpdn/.local/lib/python2.7/site-packages/ryu

xterm -e "python ./cmd/manager.py /home/hpdn/ryu-controller/mycontroller.py --ofp-tcp-listen-port=6663 --verbose" &
xterm -e "python ./cmd/manager.py /home/hpdn/ryu-controller/mycontroller.py --ofp-tcp-listen-port=6662 --verbose" &


