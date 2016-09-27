from tkinter import filedialog
import json
import os

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
json_abs_file_path = os.path.join(os.path.realpath(os.path.join(os.getcwd(), os.pardir)), json_base_path)
logger.debug("JSON file path: %s" % str(json_abs_file_path))

# define options for opening or saving a file
file_opts = options = {}
# options['defaultextension'] = '.txt'
# options['filetypes'] = [('all files', '.*'), ('text files', '.txt')]
# options['filetypes'] = [('Network Traffic Captures', '*.pcapng *.pcap *.cap'), ('Pcap-ng files', '*.pcapng'),
#                         ('Pcap files', '*.pcap'), ('text files', '*.txt'), ('all files', '.*')]
options['filetypes'] = [('JSON files', '*.json')]
options['initialdir'] = json_abs_file_path
# options['initialfile'] = 'myfile.txt'
# options['parent'] = root
# options['title'] = 'This is a title'
options['multiple'] = 'True'

# selected_file_path = filedialog.askdirectory(initialdir=json_abs_file_path, title='Select File')
selected_file_path = filedialog.askopenfilenames(**file_opts)
logger.debug("JSON file path: %s" % str(selected_file_path))        # <--- List
logger.debug("JSON file path: %s" % str(selected_file_path[0]))     # <--- Item in list

# Selecting just the data from a single file
with open(selected_file_path[0]) as json_data_file:
    data = json.load(json_data_file)
    logger.debug("Filename: %s" % data['filename'])
    logger.debug("1st Feature name: %s" % data['props'][0]['feature_name'])
    logger.debug("1st Feature 1st Value: %s" % data['props'][0]['values'][0])
    logger.debug("2nd Feature name: %s" % data['props'][1]['feature_name'])
    logger.debug("2nd Feature 1st Value: %s" % data['props'][1]['values'][0])

