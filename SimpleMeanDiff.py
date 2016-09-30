from TunnelMiner import TunnelMiner
import logging

import math
import numpy as np
import random
from collections import Counter

class SimpleMeanDiff(object):

    def __init__(self):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        # Load the test data sets
        self.http_data = TunnelMiner()
        self.http_data.load_sub_dataset("HTTPovDNS-Static", "All")
        # self.http_data.load_sub_dataset("http-ovDNS-test2", "All")

        self.ftp_data = TunnelMiner()
        # self.ftp_data.load_sub_dataset("FTPovDNS-UL","All")
        self.ftp_data.load_sub_dataset("FTPovDNS-DL","All")
        # self.ftp_data.load_sub_dataset("ftp-ovDNS-test-old", "All")

        # Load the ground truth values
        self.http_ground = TunnelMiner()
        self.http_ground.load_sub_dataset("HTTP-ground","HTTP-Req-Bytes-Hex")

        self.ftp_ground = TunnelMiner()
        self.ftp_ground.load_sub_dataset("FTP-ground", "FTP-Req-Bytes-Hex")


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
        predictions = []
        # Compare AGAINST http
        against_http_score = []
        # # Change the variable here depending on whether it is the HTTP dataset being tested or the FTP dataset
        for single_pcap_entropy_list in self.ftp_data.get_list_of_Entropy_lists():
        # for single_pcap_entropy_list in self.http_data.get_list_of_Entropy_lists():
            self.logger.debug("In 'get_Mean_Diff_Avg_Score_n_predict' ...")
            self.logger.debug("Length of Single PCAP list of entropies: %i" % len(single_pcap_entropy_list))

            ground_truth_list_of_lists_http = self.http_ground.get_list_of_Entropy_lists()
            self.logger.debug("Length of HTTP Ground-Truth List of lists: --> %i" % len(ground_truth_list_of_lists_http))
            self.logger.debug("Length of HTTP Ground-Truth List within List: --> %i" % len(ground_truth_list_of_lists_http[0]))
            against_http_score.append(self.do_mean_diff(single_pcap_entropy_list, ground_truth_list_of_lists_http[0], 100))

        # Compare AGAINST ftp
        against_ftp_score = []
        # # Change also HERE
        for single_pcap_entropy_list in self.ftp_data.get_list_of_Entropy_lists():
        # for single_pcap_entropy_list in self.http_data.get_list_of_Entropy_lists():
            grndTruth_list_of_lists_ftp = self.ftp_ground.get_list_of_Entropy_lists()
            self.logger.debug("Length of FTP Ground-Truth List of lists: --> %i" % len(grndTruth_list_of_lists_ftp))
            self.logger.debug("Length of FTP Ground-Truth List within List: --> %i" % len(grndTruth_list_of_lists_ftp[0]))
            against_ftp_score.append(self.do_mean_diff(single_pcap_entropy_list, grndTruth_list_of_lists_ftp[0], 100))

        self.logger.debug("HTTP Mean Diff scores len: %i" % len(against_http_score))
        self.logger.debug("FTP Mean Diff scores len: %i" % len(against_ftp_score))
        both_scores = {"vs_http": against_http_score, "vs_ftp": against_ftp_score}

        predictions = self.do_Score_Comparison(both_scores['vs_http'], both_scores['vs_ftp'])

        return predictions

    def do_Score_Comparison(self, http_score_list, ftp_score_list):
        self.logger.debug("HTTP score List Len: %i" % len(http_score_list))
        self.logger.debug("FTP score List Len: %i" % len(ftp_score_list))

        prediction_list = []
        if len(http_score_list) == len(ftp_score_list):
            for count, http_sc_val in enumerate(http_score_list):
                print("HTTP: %.3f | FTP: %.3f" % (float(http_sc_val), float(ftp_score_list[count])))
                if float(http_sc_val) < float(ftp_score_list[count]):
                    prediction_list.append("HTTP")
                else:
                    prediction_list.append("FTP")

        return prediction_list


    def getEquiSampleLen(self, fullTestSeq, fullGrndTruthSeq):
        '''
        - Determines the lengths of the two sequences
        - Selects 95% of the packets of the shorter sample
        :return:
        '''
        newSeqLen = (int(math.ceil(0.95 * len(fullTestSeq)))
                     if len(fullTestSeq) < len(fullGrndTruthSeq)
                     else int(math.ceil(0.95 * len(fullGrndTruthSeq))))
        # print("New Equalized Sequence Length: ", newSeqLen)
        return newSeqLen

    def getTwoEquiLenSamples(self, fullTestSeq, fullGrndTruthSeq):
        '''
        Given the new equivalent sample length from getEquiSampleLen():
        - Randomly select a continuous sequence of values of the given length between Packet 1 and the length of the Packet
        - Returns 2 samples of the same length; one from the test sample and one from the "ground truth"
        :return: A Dictionary containing the 2 list/seq samples (testSeq,grndTruthSeq)
        '''
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


http_vs_ftp = SimpleMeanDiff()
the_predictions = http_vs_ftp.get_Mean_Diff_Avg_Score_n_predict()
print(the_predictions)
print(Counter(the_predictions))
