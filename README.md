<h1 align="center">🚀 Packet Analyzer – Deep Packet Inspection Engine</h1>

<h2>📌 Project Overview</h2>

<p>
This project implements a <b>Deep Packet Inspection (DPI) engine</b> that analyzes network packets from a PCAP file,
classifies applications like <b>YouTube, Facebook, and Google</b>, and applies blocking rules.
</p>

<hr>

<h2>⚙️ System Workflow</h2>

<pre>
Wireshark Capture (input.pcap)
        │
        ▼
   DPI Engine
   - Parse Packets
   - Classify Applications
   - Apply Blocking Rules
        │
        ▼
Filtered Output (output.pcap)
</pre>

<hr>

<h2>🧩 Two Engine Versions</h2>

<table>
<tr>
<th>Version</th>
<th>File</th>
<th>Use Case</th>
</tr>

<tr>
<td>Simple (Single-threaded)</td>
<td><code>src/main_working.cpp</code></td>
<td>Learning and small PCAP captures</td>
</tr>

<tr>
<td>Multi-threaded</td>
<td><code>src/dpi_mt.cpp</code></td>
<td>Production and high traffic analysis</td>
</tr>
</table>

<hr>

<h2>📂 Project Structure</h2>

<pre>
packet_analyzer/

include/
  pcap_reader.h
  packet_parser.h
  sni_extractor.h
  types.h
  rule_manager.h
  connection_tracker.h
  load_balancer.h
  fast_path.h
  thread_safe_queue.h
  dpi_engine.h

src/
  pcap_reader.cpp
  packet_parser.cpp
  sni_extractor.cpp
  types.cpp
  main_working.cpp
  dpi_mt.cpp
</pre>

<hr>

<h2>🛠 Build</h2>

<h3>Simple Version</h3>

<pre>
g++ -std=c++17 -O2 -I include -o dpi_simple \
src/main_working.cpp \
src/pcap_reader.cpp \
src/packet_parser.cpp \
src/sni_extractor.cpp \
src/types.cpp
</pre>

<h3>Multi-threaded Version</h3>

<pre>
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
src/dpi_mt.cpp \
src/pcap_reader.cpp \
src/packet_parser.cpp \
src/sni_extractor.cpp \
src/types.cpp
</pre>

<hr>

<h2>▶️ Run</h2>

<pre>
./dpi_engine input.pcap output.pcap
</pre>

<h3>Blocking Example</h3>

<pre>
./dpi_engine input.pcap output.pcap --block-app YouTube --block-domain facebook
</pre>

<hr>

<p align="center">
⭐ Star the repository if you like the project!
</p>
