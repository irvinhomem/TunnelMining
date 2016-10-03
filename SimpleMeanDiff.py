from TunnelMiner import TunnelMiner
import logging

import math
import numpy as np
import random
from collections import Counter

class SimpleMeanDiff(object):

    def __init__(self, test_data_lbl):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        # Load the test data sets ----------------------------------
        self.test_dataset_label = test_data_lbl
        self.test_dataset = TunnelMiner()
        if self.test_dataset_label == "HTTPovDNS-Static":
            # self.http_data = TunnelMiner()
            # self.http_data.load_sub_dataset("HTTPovDNS-Static", "All")
            self.test_dataset.load_sub_dataset("HTTPovDNS-Static", "All")
            # self.http_data.load_sub_dataset("http-ovDNS-test2", "All")
        elif self.test_dataset_label == "FTPovDNS-DL":
            # self.ftp_data = TunnelMiner()
            # self.ftp_data.load_sub_dataset("FTPovDNS-UL","All")
            # self.ftp_data.load_sub_dataset("FTPovDNS-DL","All")
            self.test_dataset.load_sub_dataset("FTPovDNS-DL", "All")
            # self.ftp_data.load_sub_dataset("ftp-ovDNS-test-old", "All")
        elif self.test_dataset_label == "HTTP-S-ovDNS-Static":
            # self.http_s_data = TunnelMiner()
            # self.http_s_data.load_sub_dataset("HTTP-S-ovDNS-Static", "All")
            self.test_dataset.load_sub_dataset("HTTP-S-ovDNS-Static", "All")
        elif self.test_dataset_label == "POP3ovDNS-DL":
            # self.pop3_data = TunnelMiner()
            # self.pop3_data.load_sub_dataset("POP3ovDNS-DL", "All")
            self.test_dataset.load_sub_dataset("POP3ovDNS-DL", "All")


        # Load the ground truth values -----------------------------
        self.http_ground = TunnelMiner()
        self.http_ground.load_sub_dataset("HTTP-ground","HTTP-Req-Bytes-Hex")

        self.ftp_ground = TunnelMiner()
        self.ftp_ground.load_sub_dataset("FTP-ground", "FTP-Req-Bytes-Hex")

        self.http_s_ground = TunnelMiner()
        self.http_s_ground.load_sub_dataset("HTTP-S-ground", "HTTP-S-Req-Bytes-Hex")

        self.pop3_ground = TunnelMiner()
        self.pop3_ground.load_sub_dataset("POP3-ground", "POP3-Req-Bytes-Hex")


    def do_mean_diff(self, testCapList, grndTruthList, sampleRounds):
        runningSum = []
        if sampleRounds > 0:
            for i in range(sampleRounds):
                twoSampleSet = self.getTwoEquiLenSamples(testCapList, grndTruthList)
                runningSum.append(self.calcMeanDiff(twoSampleSet))

        self.logger.debug("Running Sum Len: %i" % len(runningSum))
        avg = np.average(runningSum)

        return  avg

    def calcMeanDiff(self, twoSampleDict):

        meanTestSeq = np.average(twoSampleDict['testSeq'])
        meanGrndTruthSeq = np.average(twoSampleDict['grndTruthSeq'])
        meanDiff = abs(meanTestSeq - meanGrndTruthSeq)

        return meanDiff

    def get_Mean_Diff_Avg_Score_n_predict(self):

        # test_dataset = None
        # if test_dataset_label == "ftp":
        #     test_dataset = self.ftp_data.get_list_of_Entropy_lists()
        # elif test_dataset_label == "http":
        #     test_dataset = self.http_data.get_list_of_Entropy_lists()
        # elif test_dataset_label == "http_s":
        #     test_dataset = self.http_s_data.get_list_of_Entropy_lists()
        # elif test_dataset_label == "pop3":
        #     test_dataset = self.pop3_data.get_list_of_Entropy_lists()

        predictions = []
        # Compare AGAINST http
        against_http_score = []
        # # Change the variable here depending on whether it is the HTTP dataset being tested or the FTP dataset
        for single_pcap_entropy_list in self.test_dataset.get_list_of_Entropy_lists():
            self.logger.debug("In 'get_Mean_Diff_Avg_Score_n_predict' ...")
            self.logger.debug("Length of Single PCAP list of entropies: %i" % len(single_pcap_entropy_list))

            ground_truth_list_of_lists_http = self.http_ground.get_list_of_Entropy_lists()
            self.logger.debug("Length of HTTP Ground-Truth List of lists: --> %i" % len(ground_truth_list_of_lists_http))
            self.logger.debug("Length of HTTP Ground-Truth List within List: --> %i" % len(ground_truth_list_of_lists_http[0]))
            against_http_score.append(self.do_mean_diff(single_pcap_entropy_list, ground_truth_list_of_lists_http[0], 100))

        # Compare AGAINST ftp
        against_ftp_score = []
        # # Change also HERE
        for single_pcap_entropy_list in self.test_dataset.get_list_of_Entropy_lists():
            grndTruth_list_of_lists_ftp = self.ftp_ground.get_list_of_Entropy_lists()
            self.logger.debug("Length of FTP Ground-Truth List of lists: --> %i" % len(grndTruth_list_of_lists_ftp))
            self.logger.debug("Length of FTP Ground-Truth List within List: --> %i" % len(grndTruth_list_of_lists_ftp[0]))
            against_ftp_score.append(self.do_mean_diff(single_pcap_entropy_list, grndTruth_list_of_lists_ftp[0], 100))

        # Compare AGAINST http-s
        against_http_s_score = []
        # # Change also HERE
        for single_pcap_entropy_list in self.test_dataset.get_list_of_Entropy_lists():
            grndTruth_list_of_lists_http_s = self.http_s_ground.get_list_of_Entropy_lists()
            self.logger.debug("Length of HTTP-S Ground-Truth List of lists: --> %i" % len(grndTruth_list_of_lists_http_s))
            self.logger.debug(
                "Length of HTTP-S Ground-Truth List within List: --> %i" % len(grndTruth_list_of_lists_http_s[0]))
            against_http_s_score.append(self.do_mean_diff(single_pcap_entropy_list, grndTruth_list_of_lists_http_s[0], 100))

        # Compare AGAINST pop3
        against_pop3_score = []
        # # Change also HERE
        for single_pcap_entropy_list in self.test_dataset.get_list_of_Entropy_lists():
            grndTruth_list_of_lists_pop3 = self.pop3_ground.get_list_of_Entropy_lists()
            self.logger.debug("Length of POP3 Ground-Truth List of lists: --> %i" %
                              len(grndTruth_list_of_lists_pop3))
            self.logger.debug("Length of POP3 Ground-Truth List within List: --> %i" %
                              len(grndTruth_list_of_lists_pop3[0]))
            against_pop3_score.append(self.do_mean_diff(single_pcap_entropy_list, grndTruth_list_of_lists_pop3[0], 100))

        self.logger.debug("HTTP Mean Diff scores len: %i" % len(against_http_score))
        self.logger.debug("FTP Mean Diff scores len: %i" % len(against_ftp_score))
        self.logger.debug("HTTP-S Mean Diff scores len: %i" % len(against_http_s_score))
        self.logger.debug("POP3 Mean Diff scores len: %i" % len(against_pop3_score))

        all_4_scores = {"vs_http": against_http_score, "vs_ftp": against_ftp_score,
                        "vs_http_s": against_http_s_score, "vs_pop3": against_pop3_score}

        predictions = self.do_Score_Comparison(all_4_scores)

        return predictions

    def do_Score_Comparison(self, all_scores):
        http_score_list = all_scores['vs_http']
        ftp_score_list = all_scores['vs_ftp']
        http_s_score_list = all_scores['vs_http_s']
        pop3_score_list = all_scores['vs_pop3']

        self.logger.debug("HTTP score List Len: %i" % len(http_score_list))
        self.logger.debug("FTP score List Len: %i" % len(ftp_score_list))
        self.logger.debug("HTTP_S score List Len: %i" % len(http_s_score_list))
        self.logger.debug("POP3 score List Len: %i" % len(pop3_score_list))

        prediction_list = []
        if len(http_score_list) == len(ftp_score_list) and len(http_s_score_list) == len(pop3_score_list):
            for count, http_sc_val in enumerate(http_score_list):
                print("HTTP: %.3f | FTP: %.3f | HTTP_S: %.3f | POP3: %.3f" %
                      (float(http_sc_val), float(ftp_score_list[count]),
                       float(http_s_score_list[count]), float(pop3_score_list[count])))
                if float(http_sc_val) < float(ftp_score_list[count] and
                                                              float(http_sc_val) < float(http_s_score_list[count]) and
                                                              float(http_sc_val) < float(pop3_score_list[count])):
                    prediction_list.append("HTTP")
                elif float(ftp_score_list[count]) < float(http_s_score_list[count]) and float(pop3_score_list[count]):
                    prediction_list.append("FTP")
                elif float(http_s_score_list[count]) < float(pop3_score_list[count]):
                    prediction_list.append("HTTPS")
                else:
                    prediction_list.append("POP3")
        else:
            self.logger.debug("Something wrong with length of score lists")
            self.logger.debug("HTTP Score list len: %i" % len(http_score_list))
            self.logger.debug("FTP Score list len: %i" % len(ftp_score_list))
            self.logger.debug("HTTP-S Score list len: %i" % len(http_s_score_list))
            self.logger.debug("POP3 Score list len: %i" % len(pop3_score_list))

        return prediction_list


    def getEquiSampleLen(self, fullTestSeq, fullGrndTruthSeq):
        '''
        - Determines the lengths of the two sequences
        - Selects 90% of the packets of the shorter sample (used 95% at some point)
        :return:
        '''
        newSeqLen = (int(math.ceil(0.90 * len(fullTestSeq)))
                     if len(fullTestSeq) < len(fullGrndTruthSeq)
                     else int(math.ceil(0.90 * len(fullGrndTruthSeq))))
        # print("New Equalized Sequence Length: ", newSeqLen)
        return newSeqLen

    def getTwoEquiLenSamples(self, fullTestSeq, fullGrndTruthSeq):
        '''
        Given the new equivalent sample length from getEquiSampleLen():
        - Randomly select a continuous sequence of values of the given length between Packet 1 and the length of the Packet
        - Returns 2 samples of the same length; one from the test sample and one from the "ground truth"
        :return: A Dictionary containing the 2 list/seq samples (testSeq,grndTruthSeq)
        '''
        self.logger.debug("Full-Test-Seq Len: %i" % len(fullTestSeq))
        self.logger.debug("Full-Grnd-Truth-Seq Len: %i" % len(fullGrndTruthSeq))

        if len(fullTestSeq) <= 1:
            self.logger.warning('Test Seqence length is Zero')
            exit()
        elif len(fullGrndTruthSeq) <= 1:
            self.logger.warning('Grnd Truth Seqence length is Zero')
            exit()

        newSeqLen = self.getEquiSampleLen(fullTestSeq, fullGrndTruthSeq)
        self.logger.debug('New Equalized Sequence Length: %i' % newSeqLen)

        testSeqStart = random.randint(1, len(fullTestSeq) - newSeqLen)
        self.logger.debug('Sample Test Seq Starting Point: %i' % testSeqStart)

        maxEnd_Grnd_Seq = len(fullGrndTruthSeq) - newSeqLen
        self.logger.debug('Grnd Truth Seq Max End Point: %i' % maxEnd_Grnd_Seq)
        if maxEnd_Grnd_Seq < 1:
            grndTruthSeqStart = 1
            newTestSeqList = fullTestSeq[testSeqStart:testSeqStart + (newSeqLen - 1)]
            newgrndTruthSeqList = fullGrndTruthSeq[grndTruthSeqStart:grndTruthSeqStart + (newSeqLen - 1)]
        else:
            grndTruthSeqStart = random.randint(1, len(fullGrndTruthSeq) - newSeqLen)

            newTestSeqList = fullTestSeq[testSeqStart:testSeqStart + newSeqLen]
            newgrndTruthSeqList = fullGrndTruthSeq[grndTruthSeqStart:grndTruthSeqStart + newSeqLen]

        self.logger.debug('Ground Truth Seq Starting Point: %i' % grndTruthSeqStart)

        multiSampleSeq = dict(testSeq=[], grndTruthSeq=[])
        multiSampleSeq["testSeq"] = newTestSeqList
        multiSampleSeq["grndTruthSeq"] = newgrndTruthSeqList

        # print("Test X: ", self.twoTestSamples["testSeq"])
        # print("Test Y: ", self.twoTestSamples["grndTruthSeq"])

        return multiSampleSeq


# mean_diff_tester = SimpleMeanDiff("FTPovDNS-DL")
# mean_diff_tester = SimpleMeanDiff("HTTPovDNS-Static")
# mean_diff_tester = SimpleMeanDiff("HTTP-S-ovDNS-Static")
mean_diff_tester = SimpleMeanDiff("POP3ovDNS-DL")


the_predictions = mean_diff_tester.get_Mean_Diff_Avg_Score_n_predict()

# the_predictions = mean_diff_tester.get_Mean_Diff_Avg_Score_n_predict('ftp')
# the_predictions = mean_diff_tester.get_Mean_Diff_Avg_Score_n_predict('http')
# the_predictions = mean_diff_tester.get_Mean_Diff_Avg_Score_n_predict('http_s')
# the_predictions = mean_diff_tester.get_Mean_Diff_Avg_Score_n_predict('pop3')

print(the_predictions)
print(Counter(the_predictions))
