# Reorder Calculation

To achieve a consistent and predictable degree of reordering (sequence gap) during experiments, relying strictly on periodic packet classification (like 1 in every N packets) is often not enough because network queuing and inter-arrival times affect the actual packet gap. 

By applying a fixed bandwidth pacing using `iperf3 -b <bandwidth>`, we can maintain constant queue lengths and predict the reordering gap.

## Parameters

* **$D_{slow}$**: Delay injected on the default (slow) path (e.g., 20ms)
* **$D_{fast}$**: Delay injected on the alternate (fast) path (e.g., 10ms)
* **$\Delta D$**: The time advantage of the fast path $\Delta D = D_{slow} - D_{fast}$ (in seconds).
* **$B$**: The target bandwidth paced by the sender (in bits per second).
* **$MSS$**: The TCP Maximum Segment Size (Payload size per packet), typically 1460 bytes. Let $MSS_{bits} = MSS \times 8$.

## Approximate Formula

The degree of reordering ($N_{gap}$, the number of packets the "fast" packet jumps ahead of) is effectively the number of packets sent during the time advantage window ($\Delta D$).

$$ N_{gap} \approx \frac{B \times \Delta D}{MSS \times 8} $$

### Example
If we want a packet to jump ahead by **10 packets**:
* $\Delta D = 20\text{ms} - 10\text{ms} = 10\text{ms} = 0.01\text{s}$
* $MSS = 1460\text{ bytes} \implies 11,680\text{ bits}$

Solving for Target Bandwidth ($B$):
$$ B = \frac{N_{gap} \times MSS \times 8}{\Delta D} $$
$$ B = \frac{10 \times 11,680}{0.01} = 11,680,000 \text{ bps} \approx 11.68 \text{ Mbps} $$

Command to run:
```bash
iperf3 -c <server_ip> -b 11.68M -N
```

*Note: For the most accurate calculations, ensure hardware offloading (TSO/GSO) is disabled on the sender. Furthermore, calculating the perfect target bandwidth ($B$) requires accounting for the bottleneck bandwidth capacity of your environment to avoid unintended queue buildup (bufferbloat) which creates huge variations in wait times under load. Since this formula assumes zero queue wait-time, it is strongly advised to test with lower bandwidths (e.g. `2 Mbps` or `5 Mbps`) that will confidently avoid saturating the link.*
