# Tunnel k-nearest neighbours
import logging
from TunnelMiner import TunnelMiner
import random
# import binascii as b2a
import numpy as np
from collections import OrderedDict, Counter
from operator import itemgetter

from terminaltables import AsciiTable


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
        self.all_unique_labels = []
        if self.test_dataset_label in ["HTTPovDNS-Static", "Compare-All"]:
            self.http_data = TunnelMiner()
            self.http_data.load_sub_dataset("HTTPovDNS-Static", "All")   # <--- Full HTTPovDNS-static Data set
            # self.http_data.load_sub_dataset("HTTPovDNS-Static-TEST", "All")
            # self.http_data.load_sub_dataset("HTTPovDNS-Static-TEST-20", "All")
            # self.http_data.load_sub_dataset("http-ovDNS-test2", "All")
            self.all_test_data.append(self.http_data)
            self.all_unique_labels.append(self.test_dataset_label)

        if self.test_dataset_label in ["FTPovDNS-DL", "Compare-All"]:
            self.ftp_data = TunnelMiner()
            self.ftp_data.load_sub_dataset("FTPovDNS-DL", "All")          # <--- Full FTPovDNS Data set
            # self.ftp_data.load_sub_dataset("FTPovDNS-DL-TEST", "All")
            # self.ftp_data.load_sub_dataset("FTPovDNS-DL-TEST-20", "All")
            # self.ftp_data.load_sub_dataset("ftp-ovDNS-test-old", "All")
            self.all_test_data.append(self.ftp_data)
            self.all_unique_labels.append(self.test_dataset_label)

        if self.test_dataset_label in ["HTTP-S-ovDNS-Static", "Compare-All"]:
            self.http_s_data = TunnelMiner()
            self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static", "All")
            # self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static-TEST", "All")
            # self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static-TEST-20", "All")
            self.all_test_data.append(self.http_s_data)
            self.all_unique_labels.append(self.test_dataset_label)

        if self.test_dataset_label in ["POP3ovDNS-DL", "Compare-All"]:
            self.pop3_data = TunnelMiner()
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL", "All")
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL-TEST", "All")
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL-TEST-20", "All")
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL-5-ATT", "All")
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL-3emails-ATT", "All")
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL-7emails-ATT", "All")
            self.pop3_data.load_sub_dataset("POP3ovDNS-DL-5txt-ATT", "All")
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL-Mixed", "All")
            self.all_test_data.append(self.pop3_data)
            self.all_unique_labels.append(self.test_dataset_label)

        self.logger.debug("Length of all unique labels list: %i" % len(self.all_unique_labels))
        # exit()

    def select_single_test_pcap(self, specific_label):
        for count, labeled_dataset in enumerate(self.all_test_data):
            if labeled_dataset.proto_Label == specific_label:
                self.logger.debug("Current Proto Label: %s" % specific_label)
                self.selected_pcap_json_obj = random.choice(self.all_test_data[count].all_json_data_list)
                self.logger.debug("Selected Item type: %s" % type(self.selected_pcap_json_obj))
                self.logger.debug("Selected Item Filename: %s" % self.selected_pcap_json_obj.single_json_object_data['filename'])

        return self.selected_pcap_json_obj

    def get_k_nearest_neighbours_of_single_random(self, k):
        self.logger.debug("Getting PCAP JSON entropy feature from: %s" % self.selected_pcap_json_obj.single_json_object_data['filename'])
        if self.use_reCalcEntropy == True:
            single_pcap_entropy_list = self.selected_pcap_json_obj.get_single_pcap_json_feature_entropy()
        else:
            # single_pcap_entropy_list = self.selected_pcap_json_obj.get_single_pcap_json_feature_entropy_from_file()
            single_pcap_entropy_list = self.selected_pcap_json_obj.get_single_pcap_json_feature_values_from_file(
                "DNS-Req-Qnames-Enc-Comp-Entropy-50-bytes")
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
                    # pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_entropy_from_file()
                    pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_values_from_file("DNS-Req-Qnames-Enc-Comp-Entropy-50-bytes")

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

    def get_k_nearest_neighbours_single_feature_all(self, k, feature_name):
        prediction_list = []
        unique_labels = []
        one_nn_true_lbl_false_preds_pairs = []
        knn_true_lbl_false_preds_pairs = []
        all_true_labels = []

        tp_counter_dict = {}
        knn_tp_counter_dict = {}

        error_counts_dict = {}
        knn_error_counts_dict = {}
        for count, pcap_group in enumerate(self.all_test_data):
            # tp_counter = 0
            for idx_selected, curr_pcap_json_obj in enumerate(pcap_group.all_json_data_list):
                curr_least_diff = 10.0
                least_diff_list = []

                if self.use_reCalcEntropy:  # Recalculate entropy from Hex_strings
                    curr_pcap_entropy_list = curr_pcap_json_obj.get_single_pcap_json_feature_entropy()
                else:
                    # curr_pcap_entropy_list = curr_pcap_json_obj.get_single_pcap_json_feature_entropy_from_file()
                    curr_pcap_entropy_list = curr_pcap_json_obj.get_single_pcap_json_feature_values_from_file(feature_name)

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
                            pcap_entropy_list = pcap_json_item.get_single_pcap_json_feature_values_from_file(feature_name)

                        self.logger.debug("Entropy List length: %i" % len(pcap_entropy_list))
                        entropy_avg = np.average(pcap_entropy_list)
                        self.logger.debug("Avg Entropy of Current ...in loop: %.8f" % avg_of_curr_obj)
                        diff = abs(avg_of_curr_obj - entropy_avg)
                        self.logger.debug("Avg Entropy Difference : %.8f" % diff)

                        curr_pcap_lbl = pcap_json_item.single_json_object_data['protocol']
                        curr_pcap_name = pcap_json_item.single_json_object_data['filename']
                        self.logger.debug("Current Min: %.6f" % curr_least_diff)
                        #
                        self.logger.debug("Current Length of LIST of least-diffs %i" % len(least_diff_list))

                        if len(least_diff_list) < k:
                            least_diff_list.append({'diff': diff, 'pred_label': curr_pcap_lbl, 'f_name:': curr_pcap_name})
                        else:
                            # largest = max([dict_obj['diff'] for idx, dict_obj in enumerate(least_diff.values())])
                            largest = max([dict_obj['diff'] for idx, dict_obj in enumerate(least_diff_list)])
                            if diff < largest: # least_diff.get(0)['diff']:
                                self.logger.debug("Latest / Current DIFF: %s" % diff)

                                index_to_remove = None
                                for idx, dict_pred in enumerate(least_diff_list):
                                # for idx, dict_pred in enumerate(least_diff.values()):
                                    self.logger.debug("Collected LEAST_DIFF values: %s" % dict_pred)
                                    self.logger.debug("Collected LEAST_DIFF 'diff' values: %s" % dict_pred['diff'])
                                    self.logger.debug("Collected Largest Diff in Predictions: %s" % largest)
                                    if dict_pred['diff'] == largest:
                                        self.logger.debug("Current View -  Least Diff: %s" % least_diff_list[idx])
                                        # self.logger.debug("Current View Least Diff: %s" % least_diff.get(idx))
                                        self.logger.debug("Largest Diff Item: %s" % dict_pred)
                                        self.logger.debug("Largest Diff Item INDEX: %s" % idx)
                                        index_to_remove = idx
                                        break

                                self.logger.debug("Length of List: %i" % len(least_diff_list))
                                least_diff_list.pop(index_to_remove)
                                self.logger.debug("LARGEST ITEM REMOVED")

                                # least_diff.update({len(least_diff)-1: {'diff': diff, 'pred_label': curr_pcap_lbl,'f_name:': curr_pcap_name}})
                                least_diff_list.append({'diff': diff,
                                                        'pred_label': curr_pcap_lbl,
                                                        'f_name:': curr_pcap_name})


                self.logger.debug("Average Entropy of Selected Test Object: %.8f" % avg_of_curr_obj)
                self.logger.debug("TEST SAMPLE ACTUAL LABEL: %s" % lbl_of_curr_pcap)

                self.logger.debug("Final Least Diff: %.8f" % curr_least_diff)
                # self.logger.debug("ORDERED-DICT of least-diffs from neighbours: %s" % least_diff)
                self.logger.debug("ORDERED-DICT of least-diffs from neighbours: %s" % least_diff_list)
                # self.logger.debug("ORDERED-DICT of labels: %s" % least_diff.get(0))
                # self.logger.debug("ORDERED-DICT of labels: %s" % neighbour_proto_lbls)

                truth_vs_prediction_dict = {'name': curr_pcap_json_obj.single_json_object_data['filename'],
                                            'true_lbl': lbl_of_curr_pcap,
                                            'predicted': least_diff_list}

                prediction_list.append(truth_vs_prediction_dict)

                if truth_vs_prediction_dict['true_lbl'] not in unique_labels:
                    unique_labels.append(truth_vs_prediction_dict['true_lbl'])
                    tp_counter_dict[truth_vs_prediction_dict['true_lbl']] = 0
                    knn_tp_counter_dict[truth_vs_prediction_dict['true_lbl']] = 0

                    # knn_error_counts_dict[truth_vs_prediction_dict['true_lbl'] + '-as-' + majority_label[0][0]] = 0
                    # error_counts_dict[truth_vs_prediction_dict['true_lbl'] + '-as-' + ordered_list[0]['pred_label']] = 0

                # if truth_vs_prediction_dict['true_lbl'] == truth_vs_prediction_dict['predicted'].get(0)['pred_label']:
                #Rank the list of "-k-" predictions
                ordered_list = sorted(truth_vs_prediction_dict['predicted'], key=itemgetter('diff'))
                self.logger.debug("Smallest Value in List: %s" % ordered_list[0]['diff'])
                self.logger.debug("Largest Value in List: %s" % ordered_list[len(ordered_list)-1]['diff'])

                # Check for 1-NN (One-Nearest Neighbour)
                if truth_vs_prediction_dict['true_lbl'] == ordered_list[0]['pred_label']:
                    self.logger.debug("True label from dict: %s" % truth_vs_prediction_dict['true_lbl'])
                    self.logger.debug("First Label from Dict within ORDERED-LIST: %s" % ordered_list[0]['pred_label'])
                    self.logger.debug("Length of Ranked Predictions List: %i" % len(ordered_list))
                    tp_counter_dict[truth_vs_prediction_dict['true_lbl']] += 1
                else: # Calculate prediction errors
                    str_false_pred = truth_vs_prediction_dict['true_lbl']+'-as-'+ordered_list[0]['pred_label']
                    if str_false_pred not in one_nn_true_lbl_false_preds_pairs : # New occurrence of false prediction
                        one_nn_true_lbl_false_preds_pairs.append(str_false_pred)
                        error_counts_dict[truth_vs_prediction_dict['true_lbl']+'-as-'+ordered_list[0]['pred_label']] = 1
                    else:
                        # for true_lbl in self.all_unique_labels:
                        #     if truth_vs_prediction_dict['true_lbl'] != true_lbl:
                        #         if ordered_list[0]['pred_label'] == true_lbl:
                        error_counts_dict[truth_vs_prediction_dict['true_lbl']+'-as-'+ordered_list[0]['pred_label']] +=1


                # Check for k-NN (k-Nearest Neighbours)
                if k > 1:
                    list_of_pred_labels = [pred_labels['pred_label'] for pred_labels in ordered_list]

                    # Picks majority, if there is a tie, it picks a random label
                    majority_label = Counter(list_of_pred_labels).most_common(1) # Return the one with the highest count
                    self.logger.debug("Majority Label: %s" % majority_label[0][0]) # List of lists with single item

                    if truth_vs_prediction_dict['true_lbl'] == majority_label[0][0]:
                        self.logger.debug("True label from dict: %s" % truth_vs_prediction_dict['true_lbl'])
                        self.logger.debug("Majority Label: %s" % majority_label[0][0])
                        knn_tp_counter_dict[truth_vs_prediction_dict['true_lbl']] += 1
                    else: # Calculate prediction errors
                        knn_str_false_pred = truth_vs_prediction_dict['true_lbl'] + '-as-' + majority_label[0][0]
                        if knn_str_false_pred not in knn_true_lbl_false_preds_pairs: # New occurrence of false prediction
                            knn_true_lbl_false_preds_pairs.append(knn_str_false_pred)
                            knn_error_counts_dict[truth_vs_prediction_dict['true_lbl'] + '-as-' + majority_label[0][0]] = 1
                        else:
                            # self.logger.debug("Num UNIQUE LABELS: %i : %s" % (len(self.all_unique_labels), self.all_unique_labels))
                            # if len(self.all_unique_labels) < 4: exit()
                            # for true_lbl in self.all_unique_labels:
                            #     if truth_vs_prediction_dict['true_lbl'] != true_lbl:
                            #         if majority_label[0][0] == true_lbl:
                            knn_error_counts_dict[truth_vs_prediction_dict['true_lbl'] +
                                                              '-as-' + majority_label[0][0]] += 1


        for idx, dict_item in enumerate(prediction_list):
            self.logger.debug("PCAP:[%i]-%s" % (idx, dict_item))

        self.logger.info("========================================")
        self.logger.info("1-NN True Positives: %s" % tp_counter_dict)
        self.logger.info("%i-NN True Positives: %s" % (k, knn_tp_counter_dict))
        self.logger.info("Class Label Test Summary Info: %s" % Counter(all_true_labels))
        self.logger.info("1-NN MISCLASSIFICATIONS: %s" % error_counts_dict)
        self.logger.info("%i-NN MISCLASSIFICATIONS: %s" % (k, knn_error_counts_dict))
        self.logger.info("-----------------------------------------")
        self.logger.info("Performance Measures:")
        self.logger.info("-----------------------------------------")

        # For 1-NN
        self.logger.info("1-NN:")
        self.logger.info("-------")


        all_labels_total = sum(Counter(all_true_labels).values())
        self.logger.info("All labels sum: %i" % all_labels_total)

        # Accuracy:
        all_true_pos = sum(tp_counter_dict.values())
        self.logger.info("All true positive sum: %i" % all_true_pos)
        accuracy_val = all_true_pos/all_labels_total
        self.logger.info("--> ACCURACY: %.5f" % accuracy_val)

        # Misclassification Rate:
        all_fpos_and_all_fneg = sum(error_counts_dict.values())
        self.logger.info("All False Pos + All False Neg: %i" % all_fpos_and_all_fneg)
        misclassification_rate = all_fpos_and_all_fneg/all_labels_total
        self.logger.info("--> MISCLASSIFICATION RATE: %.5f" % misclassification_rate)
        self.logger.info("-----> Also equal to (1- Accuracy): %.5f" % (1-accuracy_val))

        # Confusion Matrix
        conf_matrix_data = []
        conf_matrix_header1 = ['']
        conf_matrix_header1.append("Reference / Actual")
        col_titles = ['']
        row_data = []

        # Organize Confusion Matrix
        conf_matrix_data.append(conf_matrix_header1)
        conf_matrix_data.append(col_titles)

        # True-Positives Rate (Recall, Sensitivity) per Class
        #self.logger.debug("Len list_of_pred_labels: %i" % len(list_of_pred_labels))
        self.logger.debug("Len unique_labels: %i" % len(unique_labels))
        for label_key, label_value in tp_counter_dict.items():
            #self.logger.debug(item)
            #self.logger.info("%s : %s " % (item, tp_counter_dict[item]))
            self.logger.info("%s : %s " % (label_key, label_value))
            self.logger.info("--> True +ve Rate/RECALL/Sensitivity - %s: %s " %
                              (label_key, (label_value / Counter(all_true_labels)[label_key])))

            col_titles.append(label_key)
            pred_error_count = 0
            col_1 = label_key
            predictions_per_row = []
            predictions_per_row.append(col_1)
            # idx_counter += 1
            pred_val = 0
            for idx_ctr in range(len(col_titles)):
                pred_val = 0
                if idx_ctr == len(col_titles)-2:    # -2 because of the first entry as the row index name/label
                    #pred_val = label_value
                    predictions_per_row.append(label_value)
                else:
                    # Check for other error rates
                    for key_name, error_item_value in error_counts_dict.items():
                        if label_key in key_name.split("-as-")[1]:
                            # pred_error_count += error_counts_dict[error_item]
                            #pred_val = error_item_value
                            predictions_per_row.append(error_item_value)
                        else:
                            #pred_val = 0
                            predictions_per_row.append(0)

                # predictions_per_row.append(pred_val)


            # for idx, lbl in enumerate(col_titles):
            #     if lbl == label_value:
            #predictions_per_row.append(label_value)
                #else:
            # pred_val = 0
            # for key, error_item_value in error_counts_dict.items():
            #     if label_key in key.split("-as-")[0]:
            #         # pred_error_count += error_counts_dict[error_item]
            #         pred_val = error_item_value
            #     else:
            #         pred_val = 0
            #
            #     predictions_per_row.append(pred_val)




            conf_matrix_data.append(predictions_per_row)



        # Output the confusion matrix
        conf_matrix_table = AsciiTable(conf_matrix_data)
        #print(conf_matrix_table.table)
        self.logger.info("Confusion Matrix: \n%s" % conf_matrix_table.table)

        # Specificity (True Negative Rate)

        # Precision (Positive predictive value)



        #self.logger.debug(item[str(item)])



knn_test = tunKnn("Compare-All")
# knn_test.select_single_test_pcap("HTTPovDNS-Static")
# knn_test.select_single_test_pcap("FTPovDNS-DL")
# knn_test.select_single_test_pcap("HTTP-S-ovDNS-Static")
# knn_test.select_single_test_pcap("POP3ovDNS-DL")
# knn_test.select_single_test_pcap("POP3ovDNS-DL-TEST")

# knn_test.get_k_nearest_neighbours_of_single_random(1)

# knn_test.get_k_nearest_neighbours_all(1)
# knn_test.get_k_nearest_neighbours_single_feature_all(5, "DNS-Req-Qnames-Enc-Comp-Entropy-50-bytes")
# knn_test.get_k_nearest_neighbours_single_feature_all(5, "DNS-Req-Qnames-Enc-Comp-Entropy-20-bytes")
knn_test.get_k_nearest_neighbours_single_feature_all(5, "DNS-Req-Qnames-Enc-Comp-Entropy")    # Gives good distintion between HTTP and HTTPS
#knn_test.get_k_nearest_neighbours_single_feature_all(5, "IP-Req-Lens")                        # Gives good distinction between FTP and POP3
# knn_test.get_k_nearest_neighbours_single_feature_all(5, "DNS-Req-Lens")