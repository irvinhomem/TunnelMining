# from tkinter import filedialog
import json
import os
import matplotlib.pyplot as plt

#from scipy.stats import entropy as calc_entropy
import binascii as b2a
import re
from collections import Counter
import math
import numpy as np

import logging

class TunnelMiner(object):

    def __init__(self):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        # Set JSON base path directory
        #file_path = ""
        self.json_base_path = "TunnelFeatureExtractor/feature_base/JSON"
        self.json_abs_base_path = os.path.join(os.path.realpath(os.path.join(os.getcwd(), os.pardir)), self.json_base_path)
        self.logger.debug("JSON file path: %s" % str(self.json_abs_base_path))

        self.proto_Label = ""
        # self.feature_Label = ""
        self.all_json_data_list = []

        self.fig = None
        self.ax = None

    def load_sub_dataset(self, proto_lbl, feature_lbl):
        # Option for selecting the directory
        # selected_dir = filedialog.askdirectory(initialdir=self.json_abs_base_path, title='Select Base Location home-dir')
        # or
        selected_dir = os.path.join(self.json_abs_base_path, os.path.join(proto_lbl, feature_lbl))
        self.logger.info("JSON dir to pick from: %s" % str(selected_dir))

        file_list = os.listdir(selected_dir)
        self.logger.debug("File number in dir: %i" % len(file_list))
        self.logger.debug("1st File: %s" % str(file_list[0]))

        self.proto_Label = proto_lbl
        # self.feature_Label = feature_lbl
        #
        for single_file in file_list:
            abs_file_path = os.path.join(selected_dir, single_file)
            self.logger.debug("Curr file path: %s" % abs_file_path)
            with open(abs_file_path) as json_data_file:
                data = json.load(json_data_file)
                pcap_json_data_single = Single_PCAP_JSON(data)
                # List of Single_PCAP_JSON items
                self.all_json_data_list.append(pcap_json_data_single)

        self.logger.info("Length of Loaded list ||%s::%s|| List: %i" % (proto_lbl, feature_lbl, len(self.all_json_data_list)))
        # return self.all_json_data_list

    def get_list_of_Entropy_lists(self):
        all_pcap_entropy_lists = []
        for count, single_pcap_json in enumerate(self.all_json_data_list):
            # single_pcap_entropy_list = self.get_single_pcap_json_feature_entropy(single_pcap_json)
            single_pcap_entropy_list = single_pcap_json.get_single_pcap_json_feature_entropy()
                #
            all_pcap_entropy_lists.append(single_pcap_entropy_list)
            self.logger.debug("Length of ALL entropy list: %i" % len(all_pcap_entropy_lists))
        return all_pcap_entropy_lists

    def do_plot(self):
        subplot_row_dim = 1 # 2 # 4
        subplot_col_dim = len(self.all_json_data_list[0].single_json_object_data['props']) # 3
        self.logger.debug("Number of Columns: %i" % subplot_col_dim)

        self.fig, self.ax = plt.subplots(nrows=subplot_row_dim, ncols=subplot_col_dim,
                                         figsize=(16, 9), dpi=90, facecolor='w', squeeze=0)    #dpi=90 or dpi=140 (90 works best)
        # The "squeeze=0" parameter is important in order to ensure that
        # when the rows==1 or cols==1, it still creates a 2-Dimensional array.
        # Without the parameter a 1-D array will be created, making the self.ax[row, col].plot code below fail
        self.logger.debug("Axis type: %s" % str(self.ax))
        self.logger.debug("Axis shape: %s" % str(self.ax.shape))

        yVariable = []
        txtbox_params = dict(boxstyle='round', facecolor='wheat', alpha=0.6)
        avg_of_each_pcap =[]
        for counter, single_pcap_json in enumerate(self.all_json_data_list):
            # plt.plot(single_pcap_json['props'][1]['values'], marker="+", linestyle="none")
            for feat_num, feature in enumerate(single_pcap_json.single_json_object_data['props']):
                row_coord = 0 # 1
                col_coord = feat_num # 1

                if single_pcap_json.single_json_object_data['props'][feat_num]['feature_name'] == "DNS-Req-Qnames-Enc-Comp-Hex":
                    temp_y_var = []
                    for x, hex_str_item in enumerate(single_pcap_json.single_json_object_data['props'][feat_num]['values']):
                        # chunked_list = re.findall('..', hex_str_item)

                        encoded_str = b2a.unhexlify(hex_str_item.encode())
                        if x == 0:
                            # self.logger.debug("Length of 1st List: %i" % len(chunked_list))
                            # self.logger.debug("Chunked list: %s" % str(chunked_list))
                            # self.logger.debug("Counter on Chunked list: %s" % str(Counter(chunked_list)))
                            self.logger.debug("HEX string item: %s" % hex_str_item)
                            self.logger.debug("Encoded String: %s" % encoded_str)
                        #temp_y_var.append(calc_entropy(Counter(encoded_str)))
                        temp_y_var.append(single_pcap_json.calcEntropy(Counter(encoded_str)))
                        # temp_y_var.append(self.calcEntropy(Counter(chunked_list)))
                    # # Plot all entropies
                    yVariable = temp_y_var
                    # # Plot average entropy per pcap
                    yVariable_avg = np.average(temp_y_var)
                    avg_of_each_pcap.append(yVariable_avg)
                    # yVariable = [12,34,45]
                else:
                    yVariable = single_pcap_json.single_json_object_data['props'][feat_num]['values']
                    # yVariable = [12, 16, 20]

                self.ax[row_coord, col_coord].plot(yVariable, marker="+", linestyle="none")
                plotTitle = single_pcap_json.single_json_object_data['protocol'] + ' || ' + \
                            single_pcap_json.single_json_object_data['props'][feat_num]['feature_name']
                self.ax[row_coord, col_coord].set_title(plotTitle, size=8)
                self.ax[row_coord, col_coord].tick_params(axis='both', labelsize='7')

            self.fig.suptitle(single_pcap_json.single_json_object_data['protocol'], size=16)

        # self.fig.suptitle(single_pcap_json['protocol'], size=16)
        avg_of_ALL_pcaps = np.average(avg_of_each_pcap)
        self.logger.debug("Average for ALL pcaps in THIS set: %.4f" % avg_of_ALL_pcaps)

        self.fig.tight_layout()
        self.fig.subplots_adjust(top=0.92)
        self.fig.show()
        self.fig.waitforbuttonpress(timeout=-1)

class Single_PCAP_JSON(object):

    def __init__(self, json_data):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        self.single_json_object_data = json_data

    def get_single_pcap_json_feature_entropy_from_file(self):
        pcap_json_item = self.single_json_object_data
        single_pcap_entropy_list = None
        for feat_num, feature in enumerate(pcap_json_item['props']):
            self.logger.debug("Json Number of features: %s" % len(pcap_json_item['props']))
            self.logger.debug("Json features: %s" % len(pcap_json_item['props'][feat_num]))
            self.logger.debug("Json Data Feature Name: %s" % str(pcap_json_item['props'][feat_num]['feature_name']))
            if pcap_json_item['props'][feat_num]['feature_name'] in ["DNS-Req-Qnames-Enc-Comp-Entropy",
                                                                       "HTTP-Req-Bytes-Entropy",
                                                                       "FTP-Req-Bytes-Entropy",
                                                                       "HTTP-S-Req-Bytes-Entropy",
                                                                       "POP3-Req-Bytes-Entropy"]:
                single_pcap_entropy_list = pcap_json_item['props'][feat_num]['values']

                # for x, hex_str_item in enumerate(pcap_json_item['props'][feat_num]['values']):
                #     # chunked_list = re.findall('..', hex_str_item)
                #
                #     encoded_str = b2a.unhexlify(hex_str_item.encode())
                #     if x == 0:
                #         # self.logger.debug("Length of 1st List: %i" % len(chunked_list))
                #         # self.logger.debug("Chunked list: %s" % str(chunked_list))
                #         # self.logger.debug("Counter on Chunked list: %s" % str(Counter(chunked_list)))
                #         self.logger.debug("HEX string item: %s" % hex_str_item)
                #         self.logger.debug("Encoded String: %s" % encoded_str)
                #     # entropy_list.append(calc_entropy(Counter(encoded_str)))
                #     single_pcap_entropy_list.append(self.calcEntropy(Counter(encoded_str)))
                #     # entropy_list.append(self.calcEntropy(Counter(chunked_list)))
                # self.logger.debug("Length of Single PCAP entropy list: %i" % len(single_pcap_entropy_list))

        return single_pcap_entropy_list

    def get_single_pcap_json_feature_entropy(self):
        pcap_json_item = self.single_json_object_data
        single_pcap_entropy_list = []
        for feat_num, feature in enumerate(pcap_json_item['props']):
            self.logger.debug("Json Number of features: %s" % len(pcap_json_item['props']))
            self.logger.debug("Json features: %s" % len(pcap_json_item['props'][feat_num]))
            self.logger.debug("Json Data Feature Name: %s" % str(pcap_json_item['props'][feat_num]['feature_name']))
            if pcap_json_item['props'][feat_num]['feature_name'] in ["DNS-Req-Qnames-Enc-Comp-Hex",
                                                                       "HTTP-Req-Bytes-Hex",
                                                                       "FTP-Req-Bytes-Hex",
                                                                       "HTTP-S-Req-Bytes-Hex",
                                                                       "POP3-Req-Bytes-Hex"]:
                for x, hex_str_item in enumerate(pcap_json_item['props'][feat_num]['values']):
                    # chunked_list = re.findall('..', hex_str_item)

                    encoded_str = b2a.unhexlify(hex_str_item.encode())
                    if x == 0:
                        # self.logger.debug("Length of 1st List: %i" % len(chunked_list))
                        # self.logger.debug("Chunked list: %s" % str(chunked_list))
                        # self.logger.debug("Counter on Chunked list: %s" % str(Counter(chunked_list)))
                        self.logger.debug("HEX string item: %s" % hex_str_item)
                        self.logger.debug("Encoded String: %s" % encoded_str)
                    # entropy_list.append(calc_entropy(Counter(encoded_str)))
                    single_pcap_entropy_list.append(self.calcEntropy(Counter(encoded_str)))
                    # entropy_list.append(self.calcEntropy(Counter(chunked_list)))
                self.logger.debug("Length of Single PCAP entropy list: %i" % len(single_pcap_entropy_list))
        return single_pcap_entropy_list

    def calcEntropy(self, myFreqDict):
        '''
        Entropy calculation function
        H(x) = sum [p(x)*log(1/p)] for i occurrences of x
        Arguments: Takes a dictionary containing byte/char keys and their frequency as the value
        '''
        h = 0.0
        for aKey in myFreqDict:
            # Calculate probability of each even occurrence
            prob = myFreqDict[aKey]/sum(myFreqDict.values())
            # Entropy formula
            h += prob * math.log((1/prob),2)
        return h



# Start of code for testing
# # HTTP
# httpTM = TunnelMiner()
# # httpTM.load_sub_dataset("HTTPovDNS-Static","All")
# httpTM.load_sub_dataset("HTTPovDNS-Dyn","All")
# httpTM.do_plot()

# # FTP
# ftpTM = TunnelMiner()
# # ftpTM.load_sub_dataset("FTPovDNS-UL","All")
# ftpTM.load_sub_dataset("FTPovDNS-DL","All")
# ftpTM.do_plot()

# # HTTPS
# https_TM = TunnelMiner()
# # https_TM.load_sub_dataset("HTTP-S-ovDNS-Static","All")
# https_TM.load_sub_dataset("HTTP-S-ovDNS-Dyn","All")
# https_TM.do_plot()

# # POP3
# pop3TM = TunnelMiner()
# pop3TM.load_sub_dataset("POP3ovDNS-DL","All")
# pop3TM.do_plot()
