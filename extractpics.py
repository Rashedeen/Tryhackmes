import os
import re
import subprocess
from scapy.all import rdpcap, TCP
from tqdm import tqdm

PCAP_FILE = r"C:\Users\ASUS\Documents\firewallpy\security-footage-1648933966395.pcap"
OUTPUT_DIR = "frames"
VIDEO_FILE = "output_video.mp4"

def extract_tcp_stream(pcap_path):
    packets = rdpcap(pcap_path)
    tcp_payload = b""

    print("[*] Reassembling TCP stream...")
    for pkt in tqdm(packets):
        if TCP in pkt and pkt[TCP].payload:
            tcp_payload += bytes(pkt[TCP].payload)

    return tcp_payload

def extract_mjpeg_frames(data, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print("[*] Extracting MJPEG frames...")

    count = 0
    start = 0
    while True:
        start_idx = data.find(b'\xff\xd8', start)
        end_idx = data.find(b'\xff\xd9', start_idx)

        if start_idx == -1 or end_idx == -1:
            break

        frame = data[start_idx:end_idx + 2]
        with open(os.path.join(output_dir, f"frame_{count:05d}.jpg"), "wb") as f:
            f.write(frame)

        count += 1
        start = end_idx + 2

    print(f"[*] Extracted {count} frames.")
    return count

def compile_video(output_dir, video_file, fps=10):
    print("[*] Compiling video with FFmpeg...")
    cmd = [
        "ffmpeg",
        "-y",
        "-framerate", str(fps),
        "-i", os.path.join(output_dir, "frame_%05d.jpg"),
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        video_file
    ]
    subprocess.run(cmd, check=True)
    print(f"[*] Video saved as {video_file}")

if __name__ == "__main__":
    tcp_data = extract_tcp_stream(PCAP_FILE)
    frame_count = extract_mjpeg_frames(tcp_data, OUTPUT_DIR)

    if frame_count > 0:
        compile_video(OUTPUT_DIR, VIDEO_FILE)
    else:
        print("[!] No frames were extracted.")





