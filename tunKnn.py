# Tunnel k-nearest neighbours
import logging
from TunnelMiner import TunnelMiner
import random
# import binascii as b2a
import numpy as np
from collections import OrderedDict, Counter


class tunKnn(object):

    def __init__(self, test_data_lbl):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        self.use_reCalcEntropy = False
        self.test_dataset_label = test_data_lbl
        self.all_test_data = []

        # Test item
        self.selected_pcap_json_obj = None

        if self.test_dataset_label in ["HTTPovDNS-Static", "Compare-All"]:
            self.http_data = TunnelMiner()
            # self.http_data.load_sub_dataset("HTTPovDNS-Static", "All")   # <--- Full HTTPovDNS-static Data set
            self.http_data.load_sub_dataset("HTTPovDNS-Static-TEST", "All")
            # self.http_data.load_sub_dataset("HTTPovDNS-Static-TEST-20", "All")
            # self.http_data.load_sub_dataset("http-ovDNS-test2", "All")
            self.all_test_data.append(self.http_data)

        if self.test_dataset_label in ["FTPovDNS-DL", "Compare-All"]:
            self.ftp_data = TunnelMiner()
            # self.ftp_data.load_sub_dataset("FTPovDNS-DL", "All")          # <--- Full FTPovDNS Data set
            self.ftp_data.load_sub_dataset("FTPovDNS-DL-TEST", "All")
            # self.ftp_data.load_sub_dataset("FTPovDNS-DL-TEST-20", "All")
            # self.ftp_data.load_sub_dataset("ftp-ovDNS-test-old", "All")
            self.all_test_data.append(self.ftp_data)

        if self.test_dataset_label in ["HTTP-S-ovDNS-Static", "Compare-All"]:
            self.http_s_data = TunnelMiner()
            # self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static", "All")
            self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static-TEST", "All")
            # self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static-TEST-20", "All")
            self.all_test_data.append(self.http_s_data)

        if self.test_dataset_label in ["POP3ovDNS-DL", "Compare-All"]:
            self.pop3_data = TunnelMiner()
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL", "All")
            self.pop3_data.load_sub_dataset("POP3ovDNS-DL-TEST", "All")
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL-TEST-20", "All")
            self.all_test_data.append(self.pop3_data)

    def select_single_test_pcap(self, specific_label):
        for count, labeled_dataset in enumerate(self.all_test_data):
            if labeled_dataset.proto_Label == specific_label:
                self.logger.debug("Current Proto Label: %s" % specific_label)
                self.selected_pcap_json_obj = random.choice(self.all_test_data[count].all_json_data_list)
                self.logger.debug("Selected Item type: %s" % type(self.selected_pcap_json_obj))
                self.logger.debug("Selected Item Filename: %s" % self.selected_pcap_json_obj.single_json_object_data['filename'])

        return self.selected_pcap_json_obj

    def get_k_nearest_neighbours_of_single_random(self, k):
        if self.use_reCalcEntropy == True:
            single_pcap_entropy_list = self.selected_pcap_json_obj.get_single_pcap_json_feature_entropy()
        else:
            single_pcap_entropy_list = self.selected_pcap_json_obj.get_single_pcap_json_feature_entropy_from_file()
            # single_pcap_entropy_list = self.selected_pcap_json_obj.single_json_object_data['props'].get('feature_name': 'DNS-Req-Qnames-Enc-Comp-Entropy')['values']

        lbl_of_selected_pcap = self.selected_pcap_json_obj.single_json_object_data['protocol']
        avg_of_selected_obj = np.average(single_pcap_entropy_list)
        self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_selected_obj)

        # Create an ORDERED dictionary of size k
        # least_diff = dict.fromkeys((range(k)))
        least_diff = OrderedDict.fromkeys(range(k))
        neighbour_proto_lbls = OrderedDict.fromkeys(range(k))
        neighbour_pcap_name = OrderedDict.fromkeys(range(k))

        curr_least_diff = 10.0
        for count, pcap_group in enumerate(self.all_test_data):
            for idx, pcap_json_item in enumerate(pcap_group.all_json_data_list):
                if self.selected_pcap_json_obj.single_json_object_data['filename'] == pcap_json_item.single_json_object_data['filename']:
                    self.logger.debug("HIT CONTINUE ... to skip the chosen PCAP that is still in the list")
                    continue

                if self.use_reCalcEntropy == True:
                    pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_entropy()
                else:
                    pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_entropy_from_file()

                self.logger.debug("Entropy List length: %i" % len(pcap_entropy_list))
                entropy_avg = np.average(pcap_entropy_list)
                self.logger.debug("Avg Entropy of Current ...in loop: %.8f" % avg_of_selected_obj)
                diff = abs(avg_of_selected_obj - entropy_avg)
                self.logger.debug("Avg Entropy Difference : %.8f" % diff)
                if diff < curr_least_diff:
                    curr_least_diff = diff
                    curr_pcap_lbl = pcap_json_item.single_json_object_data['protocol']
                    curr_pcap_name = pcap_json_item.single_json_object_data['filename']
                    self.logger.debug("Current Min: %.8f" % curr_least_diff)

                    least_diff.update({len(least_diff)-1: curr_least_diff})
                    neighbour_proto_lbls.update({len(least_diff)-1: curr_pcap_lbl})
                    neighbour_pcap_name.update({len(least_diff)-1: curr_pcap_name})
                    # least_diff.move_to_end(diff, last=False)
                # if diff < max(least_diff, key=least_diff.get):
                #     self.logger.debug("Current Min: %.3f" % diff)

        self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_selected_obj)
        self.logger.debug("TEST SAMPLE ACTUAL LABEL: %s" % lbl_of_selected_pcap)
        self.logger.debug("Final Least Diff: %.8f" % curr_least_diff)
        self.logger.debug("ORDERED-DICT of least-diffs from neighbours: %s" % least_diff)
        self.logger.debug("ORDERED-DICT of labels: %s" % neighbour_proto_lbls)
        self.logger.debug("ORDERED-DICT of neighbour names: %s" % neighbour_pcap_name)

    def get_k_nearest_neighbours_all(self, k):
        prediction_list = []
        unique_labels = []
        all_true_labels = []
        tp_counter_dict = {}
        for count, pcap_group in enumerate(self.all_test_data):
            # tp_counter = 0
            for idx_selected, curr_pcap_json_obj in enumerate(pcap_group.all_json_data_list):
                # truth_vs_prediction_dict = {'name': '', 'true_lbl': '', 'predicted': ''}
                # Create an ORDERED dictionary of size k
                # least_diff = dict.fromkeys((range(k)))

                # least_diff = OrderedDict.fromkeys(range(k))
                # neighbour_proto_lbls = OrderedDict.fromkeys(range(k))
                # neighbour_pcap_names = OrderedDict.fromkeys(range(k))
                curr_least_diff = 10.0
                # least_diff = OrderedDict({'0': 10.0})
                # neighbour_proto_lbls = OrderedDict({'0': ''})
                # neighbour_pcap_names = OrderedDict({'0': ''})
                least_diff = OrderedDict()
                # least_diff_list = []
                # neighbour_proto_lbls = OrderedDict()
                # neighbour_pcap_names = OrderedDict()

                if self.use_reCalcEntropy:  # Recalculate entropy from Hex_strings
                    curr_pcap_entropy_list = curr_pcap_json_obj.get_single_pcap_json_feature_entropy()
                else:
                    curr_pcap_entropy_list = curr_pcap_json_obj.get_single_pcap_json_feature_entropy_from_file()
                lbl_of_curr_pcap = curr_pcap_json_obj.single_json_object_data['protocol']
                all_true_labels.append(lbl_of_curr_pcap) # To eventually be used for Counter
                avg_of_curr_obj = np.average(curr_pcap_entropy_list)
                self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_curr_obj)

                for grp_count, pcap_labelled_grp in enumerate(self.all_test_data):
                    for idx, pcap_json_item in enumerate(pcap_labelled_grp.all_json_data_list):
                        if curr_pcap_json_obj.single_json_object_data['filename'] == pcap_json_item.single_json_object_data['filename']:
                            self.logger.debug("HIT CONTINUE ... to skip the CURRENT chosen PCAP - that is still in the list")
                            continue

                        self.logger.debug("Current PCAP being checked against: %s" % pcap_json_item.single_json_object_data['filename'])
                        if self.use_reCalcEntropy:
                            pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_entropy()
                        else:
                            pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_entropy_from_file()

                        self.logger.debug("Entropy List length: %i" % len(pcap_entropy_list))
                        entropy_avg = np.average(pcap_entropy_list)
                        self.logger.debug("Avg Entropy of Current ...in loop: %.8f" % avg_of_curr_obj)
                        diff = abs(avg_of_curr_obj - entropy_avg)
                        self.logger.debug("Avg Entropy Difference : %.8f" % diff)

                        curr_pcap_lbl = pcap_json_item.single_json_object_data['protocol']
                        curr_pcap_name = pcap_json_item.single_json_object_data['filename']
                        self.logger.debug("Current Min: %.6f" % curr_least_diff)

                        if len(least_diff) == 0:
                            self.logger.debug("Least diff dictionary was empty = len = %i" %len(least_diff))
                            least_diff.update({k-1: {'diff': diff, 'pred_label': curr_pcap_lbl, 'f_name:': curr_pcap_name}})
                        if len(least_diff) > 0:
                            self.logger.debug("Least diff dictionary has at least 1 item | LEN = %i" % len(least_diff))

                            largest = max([dict_obj['diff'] for idx, dict_obj in enumerate(least_diff.values())])
                            if diff < largest: # least_diff.get(0)['diff']:
                                least_diff.update({len(least_diff) - 1: {'diff': diff, 'pred_label': curr_pcap_lbl,
                                                                         'f_name:': curr_pcap_name}})
                                # if k == 1:
                                #     least_diff.update({(k - 1): {'diff': diff, 'pred_label': curr_pcap_lbl,
                                #                                  'f_name:': curr_pcap_name}})
                                # elif k > 1:
                                #     least_diff.update({len(least_diff)-1: {'diff': diff, 'pred_label': curr_pcap_lbl,
                                #                                  'f_name:': curr_pcap_name}})
                                # elif len(least_diff) >= k:
                                #     for idx, dict_pred in enumerate(least_diff.values()):
                                #         self.logger.debug("k > 1 loop values: %s" % dict_pred)
                                #         if dict_pred['diff'] == largest:
                                #             self.logger.debug("Largest Diff Item: %s" % dict_pred)
                                #             self.logger.debug("Largest Diff Item INDEX: %s" % idx)
                                #             least_diff.pop(idx)
                                #             least_diff.update({len(least_diff): {'diff': diff, 'pred_label': curr_pcap_lbl,
                                #                              'f_name:': curr_pcap_name}})


                            # else:
                            #     if len(least_diff_list) < k:
                            #         # least_diff_list.append({'diff': diff, 'pred_label': curr_pcap_lbl, 'f_name:': curr_pcap_name})
                            #         least_diff.update({'diff': diff, 'pred_label': curr_pcap_lbl, 'f_name:': curr_pcap_name})
                            #     else:
                            #         # largest = max(items['diff'] for idx, items in enumerate(least_diff_list))
                            #         largest = max(items['diff'] for idx, items in enumerate(least_diff))
                            #
                            #         if diff < largest:
                            #             for idx, dict_obj in least_diff.items():
                            #                 if dict_obj['diff'] == largest:
                            #                     self.logger.debug("Largest Diff Item: %s" % dict_obj)
                            #                     least_diff.pop(idx)
                            #                     least_diff.update({'diff': diff, 'pred_label': curr_pcap_lbl, 'f_name:': curr_pcap_name})

                            # if diff < largest:
                                # least_diff_list.pop(least_diff_list.index(max(least_diff_list)))

                        # if len(least_diff) < k:
                        #     if len(least_diff) == 0:
                        #         curr_least_diff = 10.0
                        #         if diff < curr_least_diff:
                        #             curr_least_diff = diff
                        #
                        #             least_diff.update({0: curr_least_diff})
                        #     elif len(least_diff) > 0:
                        #         if diff < least_diff.get(len(least_diff)-1):
                        #             least_diff.


                        # if len(least_diff) >= k or len(least_diff) == 1:
                        #     if diff < least_diff.get(len(least_diff) - 1):  # curr_least_diff:
                        #         curr_least_diff = diff
                        #         curr_pcap_lbl = pcap_json_item.single_json_object_data['protocol']
                        #         curr_pcap_name = pcap_json_item.single_json_object_data['filename']
                        #         self.logger.debug("Current Min: %.8f" % curr_least_diff)
                        #
                        #         # Update FIRST or LAST
                        #         least_diff.update({len(least_diff) - 1: curr_least_diff})
                        #         neighbour_proto_lbls.update({len(least_diff) - 1: curr_pcap_lbl})
                        #         neighbour_pcap_names.update({len(least_diff) - 1: curr_pcap_name})
                        # elif 0 < len(least_diff) < k:
                        #     if diff <= least_diff.get(len(least_diff)-1): # curr_least_diff:
                        #         curr_least_diff = diff
                        #         curr_pcap_lbl = pcap_json_item.single_json_object_data['protocol']
                        #         curr_pcap_name = pcap_json_item.single_json_object_data['filename']
                        #         self.logger.debug("Current Min: %.8f" % curr_least_diff)
                        #
                        #         # ADD
                        #         least_diff.update({len(least_diff)-1: curr_least_diff})
                        #         neighbour_proto_lbls.update({len(least_diff)-1: curr_pcap_lbl})
                        #         neighbour_pcap_names.update({len(least_diff)-1: curr_pcap_name})


                self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_curr_obj)
                self.logger.debug("TEST SAMPLE ACTUAL LABEL: %s" % lbl_of_curr_pcap)

                self.logger.debug("Final Least Diff: %.8f" % curr_least_diff)
                self.logger.debug("ORDERED-DICT of least-diffs from neighbours: %s" % least_diff)
                self.logger.debug("ORDERED-DICT of labels: %s" % least_diff.get(0))
                # self.logger.debug("ORDERED-DICT of labels: %s" % neighbour_proto_lbls)

                # truth_vs_prediction_dict = {'name': curr_pcap_json_obj.single_json_object_data['filename'],
                #                             'true_lbl': lbl_of_curr_pcap,
                #                             'predicted': neighbour_proto_lbls,
                #                             'least_diffs': least_diff,
                #                             'closest_pcap': neighbour_pcap_names}

                truth_vs_prediction_dict = {'name': curr_pcap_json_obj.single_json_object_data['filename'],
                                            'true_lbl': lbl_of_curr_pcap,
                                            'predicted': least_diff}

                prediction_list.append(truth_vs_prediction_dict)

                if truth_vs_prediction_dict['true_lbl'] not in unique_labels:
                    unique_labels.append(truth_vs_prediction_dict['true_lbl'])
                    tp_counter_dict[truth_vs_prediction_dict['true_lbl']] = 0
                if truth_vs_prediction_dict['true_lbl'] == truth_vs_prediction_dict['predicted'].get(0)['pred_label']:
                    self.logger.debug("True label from dict: %s" % truth_vs_prediction_dict['true_lbl'])
                    self.logger.debug("True label from ORDERED-DICT within Dict: %s" %
                                      truth_vs_prediction_dict['predicted'].get(0))
                    tp_counter_dict[truth_vs_prediction_dict['true_lbl']] += 1


        # all_true_labels = []
        # true_positives_list = []
        for idx, dict_item in enumerate(prediction_list):
            self.logger.debug("PCAP:[%i]-%s" % (idx, dict_item))
            # # To eventually get count of number of items per class-label
            # all_true_labels.append(dict_item['true_lbl'])
            #
            # for single_label in unique_labels:
            #
            #     if dict_item['true_lbl'] == dict_item['predicted']['0']:

        self.logger.info("----------------------------------------")
        self.logger.info("True Positives: %s" % tp_counter_dict)
        self.logger.info("Class Label Test Summary Info: %s" % Counter(all_true_labels))



knn_test = tunKnn("Compare-All")
# knn_test.select_single_test_pcap("HTTPovDNS-Static")
# knn_test.select_single_test_pcap("FTPovDNS-DL")
# knn_test.select_single_test_pcap("HTTP-S-ovDNS-Static")
# knn_test.select_single_test_pcap("POP3ovDNS-DL")
# knn_test.select_single_test_pcap("POP3ovDNS-DL-TEST")

# knn_test.get_k_nearest_neighbours_of_single_random(1)

knn_test.get_k_nearest_neighbours_all(2)