import logging
from scapy.all import ARP, Ether, srp
import socket
from datetime import datetime
from typing import List, Dict
from ..models import Asset
from sqlmodel import Session, select

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, subnet: str = None):
        if not subnet:
            # Try to guess local subnet
            self.subnet = self._get_local_subnet()
        else:
            self.subnet = subnet

    def _get_local_subnet(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def scan(self) -> List[Dict]:
        """
        Performs an ARP sweep to find active devices in the subnet.
        """
        logger.info(f"Scanning subnet: {self.subnet}")
        try:
            arp = ARP(pdst=self.subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=3, verbose=0)[0]

            devices = []
            for sent, received in result:
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    hostname = f"Unknown-{received.psrc}"
                
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'hostname': hostname
                })
            
            return devices
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return []

    def sync_assets(self, session: Session):
        """
        Scans and updates the Asset table in the database.
        """
        discovered_devices = self.scan()
        for dev in discovered_devices:
            statement = select(Asset).where(Asset.hostname == dev['hostname'])
            asset = session.exec(statement).first()
            
            if asset:
                asset.ip_address = dev['ip']
                asset.mac_address = dev['mac']
                asset.last_seen = datetime.utcnow()
                session.add(asset)
            else:
                new_asset = Asset(
                    hostname=dev['hostname'],
                    ip_address=dev['ip'],
                    mac_address=dev['mac'],
                    is_managed=False
                )
                session.add(new_asset)
        
        session.commit()
        logger.info(f"Synced {len(discovered_devices)} assets to database.")
