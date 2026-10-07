# can-log-analyzer
Python tool to parse, summarise, plot and flag anomalies in CSV logs written by an STM32 + FatFS SD-card logger (sensor data received over CAN).

Features
Reads both log formats: id,value and timestamp_ms,id,value
Per-sensor summary: samples, min/max/mean/std, average period, worst gap between samples
Spike detection with a Hampel filter (rolling median + MAD), plus optional hard limits
Skips headers and corrupted lines (counts them, since SD writes can be cut off by power loss)
Saves a multi-sensor PNG with anomalies highlighted

Usage
pip install matplotlib
python log_analyzer.py --generate-sample sample_logs   # demo data, no hardware needed
python log_analyzer.py sample_logs                     # analyse a folder
python log_analyzer.py sensor1.csv --k 4 --min 0 --max 4500
