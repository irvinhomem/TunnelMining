from TunnelMiner import TunnelMiner
import logging

class SimpleMeanDiff(object):

    def __init__(self):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        # Load the test data sets
        self.http_data = TunnelMiner()
        self.http_data.load_sub_dataset("HTTPovDNS-Static", "All")

        self.ftp_data = TunnelMiner()
        self.ftp_data.load_sub_dataset()

        # Load the ground truth values
        self.http_ground = TunnelMiner()
        self.http_ground.load_sub_dataset("HTTP")

        self.ftp_ground = TunnelMiner()
        self.ftp_ground.load_sub_dataset("FTP")


    def do_mean_diff(self):

