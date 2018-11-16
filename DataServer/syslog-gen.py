#!/usr/bin/python3

import random, syslog
from sys import exit
from time import sleep
from const import PORTMAP


def main():

    port_list = []
    for port in PORTMAP:
        port_list.append(port)

    while True:
        port = random.choice(port_list)

        rand_log = '''<189>date=2018-11-14 time=07:10:32 devname=BIBA-SURYO-FGT1 devid=FGVM020000071635 logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" logtime=1542159632 srcip={}.{}.{}.{} srcport={} srcintf="port1" srcintfrole="undefined" dstip={}.{}.{}.{} dstport={} dstintf="port2" dstintfrole="undefined" sessionid=1911411692 proto=6 action="deny" policyid=0 policytype="policy" service="tcp/47225" dstcountry="India" srccountry="Netherlands" trandisp="dnat" tranip=10.51.99.12 tranport=47225 duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 appcat="unscanned" crscore=30 craction=131072 crlevel="high"
        '''.format(random.randrange(1, 256),
                   random.randrange(1, 256),
                   random.randrange(1, 256),
                   random.randrange(1, 256),
                   port,
                   random.randrange(1, 256),
                   random.randrange(1, 256),
                   random.randrange(1, 256),
                   random.randrange(1, 256),
                   port
                   )
        syslog.syslog(rand_log)
        print(rand_log)
        sleep(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit()
