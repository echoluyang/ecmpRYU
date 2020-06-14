What is implemented: a RYU ECMP controller which can send flows across paths with equal cost in a specific metric.
The project contains two parts: ecmp_controller.py and network topology files ( towpaths.py, three paths.py, complex.py)

Python 2 is used in this application.

%sudo apt-get install git gcc python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-%dev 
%python-pip

In order to run the RYU controller, need to install ryu 
% sudo pip install ryu
%sudo apt-get install mininet
%sudo apt-get install iperf 

%sudo apt-get install hping3
To run the rye application: 1. first run the mininet topology: % sudo python topo.py
2.Set the link max bandwidth data by writing in topo.txt.
The format should be: <source_switch_id> <destination_switch_id> <bandwidth> 
3. run the controller: % ru-manager —observe-links ecmp_controller.py
4. send tcp test packets % xterm h1 h2 in h1: iperf -s in h2: iperf -c 10.0.0.1 -P 30
