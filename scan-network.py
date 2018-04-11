#!/usr/bin/env python

import sys,os,getopt,time, select, subprocess
from threading import Thread
from IPy import IP

version = "2.3"
version_full = "scan-network v." + version
action = "range_scan"  # Default action

x = 100
y = 254
ping_delay = 0  # in seconds
ip = "192.168.1.*"

' Copyleft by WebNuLL no any right reserved ;-)'


def usage():
        """Shows program usage and version, lists all options"""

        print(version_full+" for GNU/Linux. A simple local network scanner.")
        print("Usage: scan-network [long GNU option] [option] from [option] to")
        print("")
        print(" --from (-f) range of ip addresses to start, default is 1")
        print(" --to (-t) range of ip addresses where to end, default is 254")
        print(" --ip (-i) mask of addresses to scan, for example 192.168.1, default 192.168.1.*")
        print(" --delay (-d) delay between pings, default is 0 second")
        print(" --load-file (-l) scan ip adresses listed in file")
        print(" --stdin (-s) grab list of ip adresses from stdin")
        print(" --help this screen")


def get_output(address):
    process = subprocess.Popen(['ping', address, '-c 1'], stdout=subprocess.PIPE)
    out, err = process.communicate()
    return out


class PingThread(Thread):
    def __init__(self, address):
        Thread.__init__(self)  # initialize thread

        # variables
        self.address = address
        self.status = -1

    def run(self):
        try:
            get = get_output(self.address)
        except OSError:
            print("Cannot execute ping, probably you don't have enough permissions to create process")
            sys.exit(1)

        lines = get.split("\n")

        for line in lines:
            # find line where is timing given
            if line.find("icmp_") > -1:
                Exp = line.split('=')
                # if response is valid
                if len(Exp) == 4:
                    self.status = Exp[3].replace(' ms', '')


def get_content(file_to_scan):
    f = open(file_to_scan, "r")
    content = f.read()
    f.close()
    return content


def main():
        global action, x, y, ping_delay, ip
        file_to_scan = ''

        try:
                opts, args = getopt.getopt(sys.argv[1:], "sl:d:i:f:t:h", ["from=", "to=", "help", "delay=", "ip=", "stdin", "load-file="]) # output=

        except getopt.GetoptError as err:
                print("Error: "+str(err)+", Try --help for usage\n\n")
                # usage()
                sys.exit(2)

        for o, a in opts:
                if o in ("-h", "--help"):
                        usage()
                        sys.exit()
                if o in ("-f", "--from"):
                        try:
                                x = float(a)
                        except ValueError:
                                print("--from argument is taking only numeric values")
                                sys.exit(2)

                if o in ("-t", "--to"):
                        try:
                                y = float(a)
                        except ValueError:
                                print ("--to argument is taking only numeric values")
                                sys.exit(2)

                if o in ("-d", "--delay"):
                        try:
                                ping_delay = float(a)
                        except ValueError:
                                print("--delay argument is taking only numeric values")
                                sys.exit(2)

                if o in ("-i", "--ip"):
                        ip = a
                if o in ("-l", "--load-file"):
                        action = "file_scan"
                        file_to_scan = a
                if o in ("-s", "--stdin"):
                        action = "stdin_scan"

        if len(opts) == 0:
            print("scan-network for GNU/Linux,  See --help for usage")
            sys.exit()

        if action == "range_scan":
            do_range_scan()
        elif action == "file_scan":
            if os.access(file_to_scan, os.R_OK):
                f = open(file_to_scan, "r")
                do_list_scan(f.read())
                f.close()
            else:
                print("Cannot open input file "+ file_to_scan)

        elif action == "stdin_scan":
            if select.select([sys.stdin,], [], [], 0.0)[0]:
                addresses = sys.stdin.read()
                do_list_scan(addresses)
            else:
                print("STDIN is empty")


def do_list_scan(inputList):
    threads = []
    lines = inputList.split("\n")

    for line in lines:  # Line == IP Adress or list of ip adresses seperated by comma ","
        ips = line.split(',')

        for ip in ips:
            try:
                IP(ip)
            except ValueError:
                continue
            else:
                ping = PingThread(ip)
                threads.append(ping)
                ping.start()

    for thread in threads:
        thread.join()
        if thread.status == -1:
            print(thread.address + " not responding, offline")
        else:
            print(thread.address + " responds in " + str(thread.status) + "ms")

        time.sleep(ping_delay)


def do_range_scan():
        global x, y, ping_delay, ip
        i = int(x)
        to = int(y)
        threads = []

        try:
            if (y-x) > 0:
                to += 1
                while i != to:
                    # use system ping and return results
                    current_ip = ip.replace('*', str(i))
                    thread = PingThread(current_ip)
                    i += 1
                    threads.append(thread)
                    thread.start()

                print("Addresses to scan: %1.0f" % (y-x))
                print("Ping " + ip.replace('*', "{" + str(int(x)) + "-" + str(int(y)) + "}"))
                print("Delay: {}s".format(ping_delay))

                for thread in threads:
                    thread.join()
                    if thread.status == -1:
                        print(thread.address+" not responding, offline")
                    else:
                        print(thread.address+" responds in "+str(thread.status)+"ms")

                    time.sleep(ping_delay)
            else:
                print ("No ip range to scan, please select valid one with --from, --to and --ip")
        except Exception as e:
            print("There was an running the scan, propably your resources are restricted. "+str(e))
            sys.exit(1)

    
if __name__ == "__main__":
    main()
