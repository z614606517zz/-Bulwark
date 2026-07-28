#!/bin/bash
# Probe HuggingFace + China mirror reachability & speed from the server. Log: /tmp/hf_probe.out
set +e
LOG=/tmp/hf_probe.out
echo "=== HF probe $(date) ===" > $LOG

probe_host () {
  local name="$1"; local url="$2"
  echo "--- $name : $url ---" >> $LOG
  curl -sI --connect-timeout 12 --max-time 20 "$url" 2>&1 | head -3 >> $LOG
  echo "connect_test rc=$?" >> $LOG
}

# connectivity
probe_host "huggingface.co" "https://huggingface.co"
probe_host "hf-mirror.com" "https://hf-mirror.com"

# speed test: ranged 16MB download of a known EMBER2024 dataset LFS file, via both HF and mirror
FILE="datasets/joyce8/EMBER2024/resolve/main/Win32_test.zip"
echo "--- speed HF (16MB range) ---" >> $LOG
curl -s -o /dev/null -w "http=%{http_code} speed=%{speed_download}B/s got=%{size_download} time=%{time_total}s\n" \
  --max-time 40 -r 0-16777215 "https://huggingface.co/$FILE" >> $LOG 2>&1
echo "--- speed MIRROR (16MB range) ---" >> $LOG
curl -s -o /dev/null -w "http=%{http_code} speed=%{speed_download}B/s got=%{size_download} time=%{time_total}s\n" \
  --max-time 40 -r 0-16777215 "https://hf-mirror.com/$FILE" >> $LOG 2>&1

echo "=== HF_PROBE_DONE ===" >> $LOG
cat $LOG
