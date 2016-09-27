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

        self.fig = None
        self.ax = None

    def load_sub_dataset(self, proto_Label, feature_Label):
        # Option for selecting the directory
        # selected_dir = filedialog.askdirectory(initialdir=self.json_abs_base_path, title='Select Base Location home-dir')
        # or
        selected_dir = os.path.join(self.json_abs_base_path, os.path.join(proto_Label, feature_Label))
        self.logger.info("JSON dir to pick from: %s" % str(selected_dir))

        file_list = os.listdir(selected_dir)
        self.logger.debug("File number in dir: %i" % len(file_list))
        self.logger.debug("1st File: %s" % str(file_list[0]))

        self.all_json_data_list = []
        for single_file in file_list:
            abs_file_path = os.path.join(selected_dir, single_file)
            self.logger.debug("Curr file path: %s" % abs_file_path)
            with open(abs_file_path) as json_data_file:
                data = json.load(json_data_file)
                self.all_json_data_list.append(data)

        self.logger.info("Length of Loaded list ||%s::%s|| List: %i" % (proto_Label, feature_Label, len(self.all_json_data_list)))
        # return all_json_data_list

    def do_plot(self):
        # subplot_row_dim = 1
        # subplot_col_dim = 1
        # self.fig, self.ax = plt.subplot(subplot_row_dim, subplot_col_dim, figsize=(16, 9), dpi=90, facecolor='w')
        # self.fig, self.ax = plt.subplot(subplot_row_dim, subplot_col_dim, figsize=(16, 9), dpi=90, facecolor='w')
        # self.fig, self.ax = plt.subplots(111)
        # yVariable = []
        # txtbox_params = dict(boxstyle='round', facecolor='wheat', alpha=0.6)
        #
        for counter, single_var in enumerate(self.all_json_data_list):
            plt.plot(single_var['props'][1]['values'], marker="+", linestyle="none")
            # self.ax.plot(single_var['props'][1]['values'], marker="+", linestyle="none")
            # row_coord = 1
            # col_coord = 1
            # self.ax[row_coord,col_coord].plot(single_var['props'][1]['values'], marker="+", linestyle="none")
        #     yVariable.append(single_var['props'][0]['values'])
        #
        #     row_coord = 1
        #     col_coord = 1
        #     self.ax[row_coord, col_coord].plot(yVariable[counter], marker="+", markeredgecolor=markercolor,
        #                                    linestyle="solid", color="blue")

        plt.show()
        # self.fig.show()

# Start of code for testing
httpTM = TunnelMiner()
httpTM.load_sub_dataset("HTTPovDNS-Static","All")
httpTM.do_plot()
