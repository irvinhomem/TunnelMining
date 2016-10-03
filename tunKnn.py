# Tunnel k-nearest neighbours
import logging
from TunnelMiner import TunnelMiner


class tunKnn(object):

    def __init__(self, test_data_lbl):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        self.test_dataset_label = test_data_lbl
        self.all_test_data = []

        self.test_dataset = TunnelMiner()
        if self.test_dataset_label in ["HTTPovDNS-Static", "Compare-All"]:
            self.test_dataset.load_sub_dataset("HTTPovDNS-Static", "All")
            # self.http_data.load_sub_dataset("http-ovDNS-test2", "All")

        elif self.test_dataset_label in ["FTPovDNS-DL", "Compare-All"]:
            self.test_dataset.load_sub_dataset("FTPovDNS-DL", "All")
            # self.ftp_data.load_sub_dataset("ftp-ovDNS-test-old", "All")

        elif self.test_dataset_label in ["HTTP-S-ovDNS-Static", "Compare-All"]:
            self.test_dataset.load_sub_dataset("HTTP-S-ovDNS-Static", "All")

        elif self.test_dataset_label == ["POP3ovDNS-DL", "Compare-All"]:
            self.test_dataset.load_sub_dataset("POP3ovDNS-DL", "All")


knn_test = tunKnn("Compare-All")