# Tunnel k-nearest neighbours
import logging
from TunnelMiner import TunnelMiner
import random
# import binascii as b2a
import numpy as np
from collections import OrderedDict


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

        # if self.test_dataset_label in ["HTTP-S-ovDNS-Static", "Compare-All"]:
        #     self.http_s_data = TunnelMiner()
        #     self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static", "All")
        #     self.all_test_data.append(self.http_s_data)
        #
        # if self.test_dataset_label in ["POP3ovDNS-DL", "Compare-All"]:
        #     self.pop3_data = TunnelMiner()
        #     self.pop3_data.load_sub_dataset("POP3ovDNS-DL", "All")
        #     self.all_test_data.append(self.pop3_data)

    def select_single_test_pcap(self, specific_label):
        for count, labeled_dataset in enumerate(self.all_test_data):
            if labeled_dataset.proto_Label == specific_label:
                self.logger.debug("Current Proto Label: %s" % specific_label)
                self.selected_pcap_json_obj = random.choice(self.all_test_data[count].all_json_data_list)
                self.logger.debug("Selected Item type: %s" % type(self.selected_pcap_json_obj))
                self.logger.debug("Selected Item Filename: %s" % self.selected_pcap_json_obj.single_json_object_data['filename'])

        return self.selected_pcap_json_obj

    def get_k_nearest_neighbours_of_single_random(self, k):
        single_pcap_entropy_list = self.selected_pcap_json_obj.get_single_pcap_json_feature_entropy()
        lbl_of_selected_pcap = self.selected_pcap_json_obj.single_json_object_data['protocol']
        avg_of_selected_obj = np.average(single_pcap_entropy_list)
        self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_selected_obj)

        # Create an ORDERED dictionary of size k
        # least_diff = dict.fromkeys((range(k)))
        least_diff = OrderedDict.fromkeys(range(k))
        neighbour_proto_lbls = OrderedDict.fromkeys(range(k))

        curr_least_diff = 10.0
        for count, pcap_group in enumerate(self.all_test_data):
            for idx, pcap_json_item in enumerate(pcap_group.all_json_data_list):
                if self.selected_pcap_json_obj.single_json_object_data['filename'] == pcap_json_item.single_json_object_data['filename']:
                    self.logger.debug("HIT CONTINUE ... to skip the chosen PCAP that is still in the list")
                    continue
                pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_entropy()
                self.logger.debug("Entropy List length: %i" % len(pcap_entropy_list))
                entropy_avg = np.average(pcap_entropy_list)
                self.logger.debug("Avg Entropy of Current ...in loop: %.8f" % avg_of_selected_obj)
                diff = abs(avg_of_selected_obj - entropy_avg)
                self.logger.debug("Avg Entropy Difference : %.8f" % diff)
                if diff < curr_least_diff:
                    curr_least_diff = diff
                    curr_pcap_lbl = pcap_json_item.single_json_object_data['protocol']
                    self.logger.debug("Current Min: %.8f" % curr_least_diff)

                    least_diff.update({len(least_diff)-1: curr_least_diff})
                    neighbour_proto_lbls.update({len(least_diff)-1: curr_pcap_lbl})
                    # least_diff.move_to_end(diff, last=False)
                # if diff < max(least_diff, key=least_diff.get):
                #     self.logger.debug("Current Min: %.3f" % diff)

        self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_selected_obj)
        self.logger.debug("TEST SAMPLE ACTUAL LABEL: %s" % lbl_of_selected_pcap)
        self.logger.debug("Final Least Diff: %.8f" % curr_least_diff)
        self.logger.debug("ORDERED-DICT of least-diffs from neighbours: %s" % least_diff)
        self.logger.debug("ORDERED-DICT of labels: %s" % neighbour_proto_lbls)

    def get_k_nearest_neighbours_all(self, k):
        prediction_list = []
        curr_least_diff = 10.0
        for count, pcap_group in enumerate(self.all_test_data):
            for idx_selected, curr_pcap_json_obj in enumerate(pcap_group.all_json_data_list):
                # truth_vs_prediction_dict = {'name': '', 'true_lbl': '', 'predicted': ''}
                # Create an ORDERED dictionary of size k
                # least_diff = dict.fromkeys((range(k)))
                least_diff = OrderedDict.fromkeys(range(k))
                neighbour_proto_lbls = OrderedDict.fromkeys(range(k))

                curr_pcap_entropy_list = curr_pcap_json_obj.get_single_pcap_json_feature_entropy()
                lbl_of_curr_pcap = curr_pcap_json_obj.single_json_object_data['protocol']
                avg_of_curr_obj = np.average(curr_pcap_entropy_list)
                self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_curr_obj)

                for idx, pcap_json_item in enumerate(pcap_group.all_json_data_list):
                    if curr_pcap_json_obj.single_json_object_data['filename'] == pcap_json_item.single_json_object_data['filename']:
                        self.logger.debug("HIT CONTINUE ... to skip the CURRENT chosen PCAP - that is still in the list")
                        continue
                    pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_entropy()
                    self.logger.debug("Entropy List length: %i" % len(pcap_entropy_list))
                    entropy_avg = np.average(pcap_entropy_list)
                    self.logger.debug("Avg Entropy of Current ...in loop: %.8f" % avg_of_curr_obj)
                    diff = abs(avg_of_curr_obj - entropy_avg)
                    self.logger.debug("Avg Entropy Difference : %.8f" % diff)
                    if diff < curr_least_diff:
                        curr_least_diff = diff
                        curr_pcap_lbl = pcap_json_item.single_json_object_data['protocol']
                        self.logger.debug("Current Min: %.8f" % curr_least_diff)

                        least_diff.update({len(least_diff)-1: curr_least_diff})
                        neighbour_proto_lbls.update({len(least_diff)-1: curr_pcap_lbl})
                        # least_diff.move_to_end(diff, last=False)
                    # if diff < max(least_diff, key=least_diff.get):
                    #     self.logger.debug("Current Min: %.3f" % diff)

                self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_curr_obj)
                self.logger.debug("TEST SAMPLE ACTUAL LABEL: %s" % lbl_of_curr_pcap)

                self.logger.debug("Final Least Diff: %.8f" % curr_least_diff)
                self.logger.debug("ORDERED-DICT of least-diffs from neighbours: %s" % least_diff)
                self.logger.debug("ORDERED-DICT of labels: %s" % neighbour_proto_lbls)

                truth_vs_prediction_dict = {'name': curr_pcap_json_obj.single_json_object_data['filename'],
                                            'true_lbl': lbl_of_curr_pcap,
                                            'predicted': neighbour_proto_lbls,
                                            'least_diffs': least_diff}

                prediction_list.append(truth_vs_prediction_dict)

        for idx, dict_item in enumerate(prediction_list):
            self.logger.debug("PCAP: [%i] - %s" % (idx, dict_item))




knn_test = tunKnn("Compare-All")
# knn_test.select_single_test_pcap("HTTPovDNS-Static")
# knn_test.select_single_test_pcap("FTPovDNS-DL")
# knn_test.select_single_test_pcap("HTTP-S-ovDNS-Static")
# knn_test.select_single_test_pcap("POP3ovDNS-DL")

# knn_test.get_k_nearest_neighbours_of_single_random(1)

knn_test.get_k_nearest_neighbours_all(1)