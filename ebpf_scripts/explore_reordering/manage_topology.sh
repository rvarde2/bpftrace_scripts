#!/bin/bash
DEV="s1-eth2"
DELAY=500ms

if [ "$#" -ne 1 ] ; then
    printf "$0: exactly 1 arguments expected\n"
    printf "Usage: ./simple_bridge_setup.sh <command>\n"
    printf "Commands:\n"
    printf "\t-h: help\n"
    printf "\t-create: create setup\n"
    printf "\t-delete: delete setup\n"
    printf "\t-loss <percent loss>: packet loss\n"
    printf "\t-reorder_on: enable ebpf based reordering\n"
    printf "\t-reorder_off: disable ebpf based reordering\n"
    exit 1
fi

case "$1" in
    -create)
        echo "[+] Setting up Bridge and Namespaces..."
        sudo ip netns add h1 && sudo ip netns add h2
        sudo ip link add name s1 type bridge
        sudo ip link add h1-eth0 type veth peer name s1-eth1
        sudo ip link add h2-eth0 type veth peer name s1-eth2
        sudo ip link set h1-eth0 netns h1 && sudo ip link set h2-eth0 netns h2
        sudo ip link set s1-eth1 master s1 && sudo ip link set s1-eth2 master s1
        sudo ip link set s1-eth1 up && sudo ip link set s1-eth2 up && sudo ip link set s1 up
        sudo ip netns exec h1 ip addr add 192.168.1.2/24 dev h1-eth0
        sudo ip netns exec h1 ip link set dev h1-eth0 up
        sudo ip netns exec h2 ip addr add 192.168.1.3/24 dev h2-eth0
        sudo ip netns exec h2 ip link set dev h2-eth0 up

        echo "[+] Setting up 3-Band PRIO on $DEV..."
     
        # In your setup block: 
		# This priomap ensures:
		# Priority 0 -> Band 1 (index 0)
		# Priority 1 -> Band 2 (index 1)
		# Priority 2 -> Band 3 (index 2)
		# Verification: sudo tc -s qdisc show dev s1-eth2
		sudo tc qdisc add dev $DEV root handle 1: prio bands 3 priomap 0 1 2 2 2 2 2 2 2 2 2 2 2 2 2 2

		# Re-attach child qdiscs
		sudo tc qdisc add dev $DEV parent 1:1 handle 10: pfifo
		sudo tc qdisc add dev $DEV parent 1:2 handle 20: netem delay $DELAY
		sudo tc qdisc add dev $DEV parent 1:3 handle 30: pfifo
		;;
	-reorder_on)
		echo "[+] Compiling and Attaching eBPF..."
		make
		sudo tc qdisc add dev $DEV clsact 2>/dev/null
		sudo tc filter add dev $DEV egress bpf da obj ebpf_reorder.o sec classifier
		;;
	-reorder_off)
		echo "[-] Removing eBPF Reorder Logic..."
		# This command deletes the specific BPF filter from the egress hook
		sudo tc filter del dev $DEV egress 2>/dev/null
		echo "[-] Reordering Stopped. Traffic will now use default Band 1."
		;;
	-loss)
		echo "[+] Setting Band 1 Loss to $2%"
		sudo tc qdisc change dev $DEV parent 1:1 handle 10: netem loss $2%
		;;
	-delete)
		sudo ip netns del h1 && sudo ip netns del h2
		sudo ip link delete name s1 type bridge
		;;
	*)
		printf "Usage: ./simple_bridge_setup.sh <command>\n"
		printf "Commands:\n"
		printf "\t-h: help\n"
		printf "\t-create: create setup\n"
		printf "\t-delete: delete setup\n"
		printf "\t-loss <percent loss>: packet loss\n"
		printf "\t-reorder_on: enable ebpf based reordering\n"
		printf "\t-reorder_off: disable ebpf based reordering\n"
		;;
esac