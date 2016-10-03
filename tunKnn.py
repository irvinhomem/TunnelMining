# Tunnel k-nearest neighbours
import logging
from TunnelMiner import TunnelMiner
import random
import binascii as b2a


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

        # Test item
        self.selected_pcap_json_obj = None

        if self.test_dataset_label in ["HTTPovDNS-Static", "Compare-All"]:
            self.http_data = TunnelMiner()
            self.http_data.load_sub_dataset("HTTPovDNS-Static", "All")
            # self.http_data.load_sub_dataset("http-ovDNS-test2", "All")
            self.all_test_data.append(self.http_data)

        if self.test_dataset_label in ["FTPovDNS-DL", "Compare-All"]:
            self.ftp_data = TunnelMiner()
            self.ftp_data.load_sub_dataset("FTPovDNS-DL", "All")
            # self.ftp_data.load_sub_dataset("ftp-ovDNS-test-old", "All")
            self.all_test_data.append(self.ftp_data)

        if self.test_dataset_label in ["HTTP-S-ovDNS-Static", "Compare-All"]:
            self.http_s_data = TunnelMiner()
            self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static", "All")
            self.all_test_data.append(self.http_s_data)

        if self.test_dataset_label in ["POP3ovDNS-DL", "Compare-All"]:
            self.pop3_data = TunnelMiner()
            self.pop3_data.load_sub_dataset("POP3ovDNS-DL", "All")
            self.all_test_data.append(self.pop3_data)

    def select_single_test_pcap(self, specific_label):
        for count, labeled_dataset in enumerate(self.all_test_data):
            if labeled_dataset.proto_Label == specific_label:
                self.logger.debug("Current Proto Label: %s" % specific_label)
                self.selected_pcap_json_obj = random.choice(self.all_test_data[count].all_json_data_list)
                self.logger.debug("Selected Item type: %s" % type(self.selected_pcap_json_obj))
                self.logger.debug("Selected Item Filename: %s" % self.selected_pcap_json_obj.single_json_object_data['filename'])

        return self.selected_pcap_json_obj

    def get_k_nearest_neighbours(self, k):
        single_pcap_entropy_list = self.selected_pcap_json_obj.get_single_pcap_json_feature_entropy()

    # def get_single_pcap_json_feature_entropy(self, pcap_json_item):
    #     single_pcap_entropy_list = []
    #     for feat_num, feature in enumerate(pcap_json_item['props']):
    #         self.logger.debug("Json Number of features: %s" % len(pcap_json_item['props']))
    #         self.logger.debug("Json features: %s" % len(pcap_json_item['props'][feat_num]))
    #         self.logger.debug("Json Data Feature Name: %s" % str(pcap_json_item['props'][feat_num]['feature_name']))
    #         if pcap_json_item['props'][feat_num]['feature_name'] in ["DNS-Req-Qnames-Enc-Comp-Hex",
    #                                                                    "HTTP-Req-Bytes-Hex",
    #                                                                    "FTP-Req-Bytes-Hex",
    #                                                                    "HTTP-S-Req-Bytes-Hex",
    #                                                                    "POP3-Req-Bytes-Hex"]:
    #             for x, hex_str_item in enumerate(pcap_json_item['props'][feat_num]['values']):
    #                 # chunked_list = re.findall('..', hex_str_item)
    #
    #                 encoded_str = b2a.unhexlify(hex_str_item.encode())
    #                 if x == 0:
    #                     # self.logger.debug("Length of 1st List: %i" % len(chunked_list))
    #                     # self.logger.debug("Chunked list: %s" % str(chunked_list))
    #                     # self.logger.debug("Counter on Chunked list: %s" % str(Counter(chunked_list)))
    #                     self.logger.debug("HEX string item: %s" % hex_str_item)
    #                     self.logger.debug("Encoded String: %s" % encoded_str)
    #                 # entropy_list.append(calc_entropy(Counter(encoded_str)))
    #                 single_pcap_entropy_list.append(self.calcEntropy(Counter(encoded_str)))
    #                 # entropy_list.append(self.calcEntropy(Counter(chunked_list)))
    #                 self.logger.debug("Length of Single PCAP entropy list: %i" % len(single_pcap_entropy_list))
    #     return single_pcap_entropy_list

knn_test = tunKnn("Compare-All")
# knn_test.select_single_test_pcap("HTTPovDNS-Static")
knn_test.select_single_test_pcap("FTPovDNS-DL")
knn_test.get_k_nearest_neighbours(1)