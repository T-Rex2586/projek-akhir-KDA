#!/usr/bin/env python3
# Copyright (c) 2024 - DDoS Detection Project
# Mininet Topology for DDoS Detection Testing
#
# Topology (as per CLAUDE.md):
# - 4 attacker hosts  (10.0.1.1-4)
# - 4 victim hosts    (10.0.2.1-4)
# - 4 legitimate hosts(10.0.3.1-4)
# - 4 Open vSwitch switches
# - 1 Ryu controller (remote, 127.0.0.1:6653)
#
# All hosts share a /16 subnet to ensure L2 reachability
# across all switches (same broadcast domain).
#
# NOTE: This script requires Mininet (Linux only).
# Usage:
#   sudo python mininet/topology.py

import os
import sys
import subprocess

try:
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info, error
    from mininet.link import TCLink
    from mininet.clean import cleanup
    MININET_AVAILABLE = True
except ImportError:
    MININET_AVAILABLE = False
    print("WARNING: Mininet not available. This script requires a Linux environment.")


def ensure_ovs_running():
    """Ensure Open vSwitch daemons are running (critical for WSL2).

    WSL2 often fails to start OVS via systemd because systemd itself
    may not be the init system. This function manually starts the
    required OVS daemons (ovsdb-server and ovs-vswitchd) if they
    are not already running.
    """
    info('*** Checking Open vSwitch status\n')

    # Create required directories
    os.makedirs('/var/run/openvswitch', exist_ok=True)
    os.makedirs('/etc/openvswitch', exist_ok=True)

    # Initialize database if it doesn't exist
    if not os.path.exists('/etc/openvswitch/conf.db'):
        info('*** Initializing OVS database\n')
        subprocess.run([
            'ovsdb-tool', 'create',
            '/etc/openvswitch/conf.db',
            '/usr/share/openvswitch/vswitch.ovsschema'
        ], check=True)

    # Start ovsdb-server if not running
    result = subprocess.run(['pgrep', '-x', 'ovsdb-server'], capture_output=True)
    if result.returncode != 0:
        info('*** Starting ovsdb-server\n')
        subprocess.run([
            'ovsdb-server',
            '--remote=punix:/var/run/openvswitch/db.sock',
            '--remote=db:Open_vSwitch,Open_vSwitch,manager_options',
            '--pidfile', '--detach', '--log-file'
        ], check=True)

    # Initialize OVS config
    subprocess.run(['ovs-vsctl', '--no-wait', 'init'], check=True)

    # Start ovs-vswitchd if not running
    result = subprocess.run(['pgrep', '-x', 'ovs-vswitchd'], capture_output=True)
    if result.returncode != 0:
        info('*** Starting ovs-vswitchd\n')
        subprocess.run([
            'ovs-vswitchd',
            '--pidfile', '--detach', '--log-file'
        ], check=True)

    # Quick sanity check
    result = subprocess.run(['ovs-vsctl', 'show'], capture_output=True, text=True)
    if result.returncode == 0:
        info('*** Open vSwitch is running OK\n')
    else:
        error('*** WARNING: Open vSwitch may not be working correctly!\n')


def create_topology():
    """Create the SDN topology for DDoS testing."""
    if not MININET_AVAILABLE:
        print("Mininet is not installed. This topology requires Linux with Mininet.")
        return

    setLogLevel('info')

    # Step 1: Ensure OVS daemons are operational
    ensure_ovs_running()

    # Step 2: Clean up any previous Mininet state (stale interfaces, bridges, etc.)
    info('*** Cleaning up previous Mininet state\n')
    cleanup()

    # Step 3: Create network
    # Using OVSSwitch (not OVSKernelSwitch) for better WSL2 compatibility
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True   # Auto-assign unique sequential MAC addresses
    )

    info('*** Adding Ryu Controller\n')
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6653)

    info('*** Adding switches\n')
    switches = []
    for i in range(1, 5):
        s = net.addSwitch(f's{i}', protocols='OpenFlow13')
        switches.append(s)

    # ----------------------------------------------------------------
    # All hosts use a /16 subnet mask so they share the same L2
    # broadcast domain and can reach each other without a router.
    # IP ranges are chosen to distinguish roles:
    #   Attackers  : 10.0.1.x
    #   Victims    : 10.0.2.x
    #   Legitimate : 10.0.3.x
    # ----------------------------------------------------------------
    info('*** Adding attacker hosts\n')
    attackers = []
    for i in range(1, 5):
        h = net.addHost(f'attacker{i}', ip=f'10.0.1.{i}/16')
        attackers.append(h)

    info('*** Adding victim hosts\n')
    victims = []
    for i in range(1, 5):
        h = net.addHost(f'victim{i}', ip=f'10.0.2.{i}/16')
        victims.append(h)

    info('*** Adding legitimate hosts\n')
    legit = []
    for i in range(1, 5):
        h = net.addHost(f'legit{i}', ip=f'10.0.3.{i}/16')
        legit.append(h)

    info('*** Creating links\n')
    # Connect attackers to switch 1
    for a in attackers:
        net.addLink(a, switches[0])

    # Connect victims to switch 2
    for v in victims:
        net.addLink(v, switches[1])

    # Connect legitimate hosts to switch 3
    for l in legit:
        net.addLink(l, switches[2])

    # Inter-switch links (star topology via s4)
    net.addLink(switches[0], switches[3])
    net.addLink(switches[1], switches[3])
    net.addLink(switches[2], switches[3])

    info('*** Starting network\n')
    net.start()

    info('*** Topology ready\n')
    info('Attackers:  attacker1-4 (10.0.1.1-4)\n')
    info('Victims:    victim1-4   (10.0.2.1-4)\n')
    info('Legitimate: legit1-4    (10.0.3.1-4)\n')
    info('\n')

    info('*** Testing connectivity (pingall)...\n')
    net.pingAll(timeout=2)

    CLI(net)
    net.stop()


if __name__ == '__main__':
    create_topology()
