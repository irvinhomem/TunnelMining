from tkinter import filedialog
import json
import os
import matplotlib

import logging

# Configure Logging
logging.basicConfig(level=logging.INFO)
# logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)
# self.logger.setLevel(logging.INFO)
logger.setLevel(logging.DEBUG)
# self.logger.setLevel(logging.WARNING)

file_path = ""
json_base_path = "TunnelFeatureExtractor/feature_base/JSON"
json_abs_base_path = os.path.join(os.path.realpath(os.path.join(os.getcwd(), os.pardir)), json_base_path)
logger.debug("JSON file path: %s" % str(json_abs_base_path))

# print(type(os.listdir(json_abs_file_path)))

selected_dir = filedialog.askdirectory(initialdir=json_abs_base_path, title='Select Base Location home-dir')
logger.debug("JSON dir to pick from: %s" % str(selected_dir))

file_list = os.listdir(selected_dir)
logger.debug("File number in dir: %i" % len(file_list))
logger.debug("1st File: %s" % str(file_list[0]))
logger.debug("2nd File: %s" % str(file_list[1]))
logger.debug("3rd File: %s" % str(file_list[2]))

# # Selecting just the data from a single file
# with open(selected_file_path[0]) as json_data_file:
#     data = json.load(json_data_file)
#     logger.debug("Filename: %s" % data['filename'])
#     logger.debug("1st Feature name: %s" % data['props'][0]['feature_name'])
#     logger.debug("1st Feature 1st Value: %s" % data['props'][0]['values'][0])
#     logger.debug("2nd Feature name: %s" % data['props'][1]['feature_name'])
#     logger.debug("2nd Feature 1st Value: %s" % data['props'][1]['values'][0])

http_ovDNS_json_data = []
for single_file in file_list:
    abs_file_path = os.path.join(selected_dir, single_file)
    logger.debug("Curr file path: %s" % abs_file_path)
    with open(abs_file_path) as json_data_file:
        data = json.load(json_data_file)
        http_ovDNS_json_data.append(data)

logger.debug("HTTP-ovDNS data set items: %i" % len(http_ovDNS_json_data))

