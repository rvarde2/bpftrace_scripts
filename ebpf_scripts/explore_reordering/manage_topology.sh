#!/bin/bash
DEV="s1-eth2"
DELAY_BASE=20ms
DELAY_REORDER=10ms

print_usage() {
    printf "Usage: ./manage_topology.sh <command>\n"
    printf "Commands:\n"
    printf "\t--help: help\n"
    printf "\t--create: create setup\n"
    printf "\t--dsack: <enable/disable/status/track>: enable, disable, track or get status of dsack\n"
    printf "\t--delete: delete setup\n"
    printf "\t--loss <percent loss|status>: packet loss or get current loss status\n"
    printf "\t--reorder <enable/disable/status>: enable, disable, or get status of ebpf based reordering\n"
    printf "\t--mark_echo <enable/disable/status>: enable, disable, or get status of ebpf based mark_echo\n"
}

if [ "$#" -gt 2 ] ; then
    printf "$0: maximum 2 arguments expected\n"
    print_usage
    exit 1
fi

case "$1" in
    --create)
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
		sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay $DELAY_BASE
		sudo tc qdisc add dev $DEV parent 1:2 handle 20: netem delay $DELAY_REORDER
		sudo tc qdisc add dev $DEV parent 1:3 handle 30: pfifo
		;;
	--dsack)
		if [ "$2" = "enable" ]; then
			echo "[+] Enabling dsack in both namespaces..."
			sudo ip netns exec h1 sysctl -w net.ipv4.tcp_dsack=1
			sudo ip netns exec h2 sysctl -w net.ipv4.tcp_dsack=1
		elif [ "$2" = "disable" ]; then
			echo "[+] Disabling dsack in both namespaces..."
			sudo ip netns exec h1 sysctl -w net.ipv4.tcp_dsack=0
			sudo ip netns exec h2 sysctl -w net.ipv4.tcp_dsack=0
		elif [ "$2" = "status" ]; then
			echo "[*] dsack status:"
			sudo ip netns exec h1 sysctl net.ipv4.tcp_dsack
			sudo ip netns exec h2 sysctl net.ipv4.tcp_dsack
		elif [ "$2" = "track" ]; then
			echo "[*] Tracking dsack in sender namespaces with tshark..."
			sudo ip netns exec h1 tshark -i h1-eth0 -Y "tcp.options.sack.dsack" 
		else
			echo "Usage: --dsack <enable|disable|status|track>"
			exit 1
		fi
		;;
	--reorder)
		if [ "$2" = "enable" ]; then
			echo "[+] Compiling and Attaching eBPF..."
			make
			sudo tc qdisc add dev $DEV clsact 2>/dev/null
			# pref 10 sets rule execution preference, does NOT affect skb->priority
			sudo tc filter add dev $DEV egress pref 10 bpf da obj ebpf_reorder.o sec classifier
		elif [ "$2" = "disable" ]; then
			echo "[-] Removing eBPF Reorder Logic..."
			# This specifically deletes only the rule with preference 10
			sudo tc filter del dev $DEV egress pref 10 2>/dev/null
			echo "[-] Reordering Stopped. Traffic will now use default Band 1."
		elif [ "$2" = "status" ]; then
			if sudo tc filter show dev $DEV egress | grep -q "ebpf_reorder.o"; then
				echo "[*] eBPF Reordering is currently: ENABLED"
			else
				echo "[*] eBPF Reordering is currently: DISABLED"
			fi
		else
			echo "Usage: --reorder <enable|disable|status>"
			exit 1
		fi
		;;
	--mark_echo)
		if [ "$2" = "enable" ]; then
			echo "[+] Compiling and Attaching eBPF mark_echo..."
			make
			sudo ip netns exec h2 tc qdisc add dev h2-eth0 clsact 2>/dev/null
			# pref 20 sets rule execution preference
			sudo ip netns exec h2 tc filter add dev h2-eth0 ingress pref 20 bpf da obj ebpf_mark_echo.o sec classifier
		elif [ "$2" = "disable" ]; then
			echo "[-] Removing eBPF mark_echo Logic..."
			sudo ip netns exec h2 tc filter del dev h2-eth0 ingress pref 20 2>/dev/null
			echo "[-] mark_echo Stopped."
		elif [ "$2" = "status" ]; then
			if sudo ip netns exec h2 tc filter show dev h2-eth0 ingress | grep -q "ebpf_mark_echo.o"; then
				echo "[*] eBPF mark_echo is currently: ENABLED"
			else
				echo "[*] eBPF mark_echo is currently: DISABLED"
			fi
		else
			echo "Usage: --mark_echo <enable|disable|status>"
			exit 1
		fi
		;;
	--loss)
		if [ "$2" = "status" ]; then
			CURRENT_LOSS=$(sudo tc qdisc show dev $DEV | grep "10: parent 1:1" | grep -o 'loss [^ ]*' | cut -d' ' -f2)
			if [ -z "$CURRENT_LOSS" ]; then
				echo "[*] Current Band 1 Loss: 0%"
			else
				echo "[*] Current Band 1 Loss: $CURRENT_LOSS"
			fi
		else
			echo "[+] Setting Band 1 Loss to $2%"
			sudo tc qdisc change dev $DEV parent 1:1 handle 10: netem loss $2%
		fi
		;;
	--delete)
		sudo ip netns del h1 && sudo ip netns del h2
		sudo ip link delete name s1 type bridge
		;;
	*)
		print_usage
		;;
esac
