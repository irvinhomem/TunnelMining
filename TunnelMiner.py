# from tkinter import filedialog
import json
import os
import matplotlib.pyplot as plt

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

        # self.proto_Label = ""
        # self.feature_Label = ""

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

        # self.proto_Label = proto_lbl
        # self.feature_Label = feature_lbl

        self.all_json_data_list = []
        for single_file in file_list:
            abs_file_path = os.path.join(selected_dir, single_file)
            self.logger.debug("Curr file path: %s" % abs_file_path)
            with open(abs_file_path) as json_data_file:
                data = json.load(json_data_file)
                self.all_json_data_list.append(data)

        self.logger.info("Length of Loaded list ||%s::%s|| List: %i" % (proto_lbl, feature_lbl, len(self.all_json_data_list)))
        # return all_json_data_list

    def do_plot(self):
        subplot_row_dim = 2 # 4
        subplot_col_dim = 3 # 3

        self.fig, self.ax = plt.subplots(subplot_row_dim, subplot_col_dim, figsize=(16, 9), dpi=90, facecolor='w')

        # yVariable = []
        txtbox_params = dict(boxstyle='round', facecolor='wheat', alpha=0.6)
        #
        for counter, single_var in enumerate(self.all_json_data_list):
            # plt.plot(single_var['props'][1]['values'], marker="+", linestyle="none")
            row_coord = 0 # 1
            col_coord = 0 # 1
            self.ax[row_coord, col_coord].plot(single_var['props'][0]['values'], marker="+", linestyle="none")
            plotTitle = single_var['protocol'] + ' || ' + single_var['props'][1]['feature_name']
            self.ax[row_coord, col_coord].set_title(plotTitle, size=8)
            self.ax[row_coord, col_coord].tick_params(axis='both', labelsize='7')

        self.fig.tight_layout()
        self.fig.show()
        self.fig.waitforbuttonpress(timeout=-1)

# Start of code for testing
httpTM = TunnelMiner()
httpTM.load_sub_dataset("HTTPovDNS-Static","All")
httpTM.do_plot()
