import logging

from collections import Counter
from terminaltables import AsciiTable

class PerformanceMeasures(object):

    def __init__(self, true_pos_counter_dict, error_counter_dict, all_labelled_samples_count_dict):
        # Configure Logging
        logging.basicConfig(level=logging.INFO)
        # logging.basicConfig(level=logging.WARNING)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        # self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.WARNING)

        self.tp_counter_dict = true_pos_counter_dict
        self.error_counts_dict = error_counter_dict
        self.all_actual_labels = all_labelled_samples_count_dict

    def get_performance_measures(self):
        # Confusion Matrix
        conf_matrix_all_row_data = []
        conf_matrix_header1 = ['']
        conf_matrix_header1.append("Predictions")
        col_titles = ['']

        # # Organize Confusion Matrix
        conf_matrix_all_row_data.append(conf_matrix_header1)

        class_labels_list = self.tp_counter_dict.keys()

        for lbl in class_labels_list:
            col_titles.append(lbl)
            self.logger.debug("Current lbl COLUMN NAME: %s" % lbl)
        self.logger.debug("Length of Column Titles list: %i" % len(col_titles))

        conf_matrix_all_row_data.append(col_titles)

        for lbl in class_labels_list:
            #col_titles.append(lbl)
            single_row_data = []
            self.logger.debug("Current Class LABEL: %s" % lbl)
            single_row_data.append(lbl)
            # Check index of current Column-Title
            #for col_idx, col_lbl in enumerate(col_titles):
            for col_idx, col_lbl in enumerate(class_labels_list):
                error_lbls = str(single_row_data[0]) + "-as-" + col_lbl
                self.logger.debug("Current Error Label: %s" % error_lbls)
                if single_row_data[0] == col_lbl:
                    single_row_data.append(self.tp_counter_dict[col_lbl])
                # elif error_counts_dict.keys() contains single_row_data[0]  and col_lbl ==
                elif error_lbls in self.error_counts_dict.keys():
                    single_row_data.append(self.error_counts_dict[error_lbls])
                else:
                    single_row_data.append(0)

            conf_matrix_all_row_data.append(single_row_data)

            #single_row_data.insert()

        # Output the confusion matrix
        conf_matrix_table = AsciiTable(conf_matrix_all_row_data)
        # print(conf_matrix_table.table)
        self.logger.info("Confusion Matrix: \n%s" % conf_matrix_table.table)

        all_labels_total = sum(Counter(self.all_actual_labels).values())
        self.logger.info("All labels sum: %i" % all_labels_total)

        # Accuracy:
        all_true_pos = sum(self.tp_counter_dict.values())
        self.logger.info("All true positive sum: %i" % all_true_pos)
        accuracy_val = all_true_pos/all_labels_total
        self.logger.info("--> ACCURACY: %.5f = %.2f%%" % (accuracy_val, accuracy_val*100))

        # Misclassification Rate:
        all_fpos_and_all_fneg = sum(self.error_counts_dict.values())
        self.logger.info("All False Pos + All False Neg: %i" % all_fpos_and_all_fneg)
        misclassification_rate = all_fpos_and_all_fneg/all_labels_total
        self.logger.info("--> MISCLASSIFICATION RATE: %.5f" % misclassification_rate)
        self.logger.debug("--> Also equal to (1- Accuracy): %.5f" % (1-accuracy_val))

        # True-Positives Rate (Recall, Sensitivity) per Class
        #self.logger.debug("Len list_of_pred_labels: %i" % len(list_of_pred_labels))
        #self.logger.debug("Len unique_labels: %i" % len(unique_labels))
        for label_key, label_pred_value in self.tp_counter_dict.items():
            #self.logger.debug(item)
            #self.logger.info("%s : %s " % (item, tp_counter_dict[item]))
            self.logger.info("%s : %s " % (label_key, label_pred_value))
            actual_specific_lbl_count = Counter(self.all_actual_labels)[label_key]
            self.logger.info("--> True Pos+ Rate/ RECALL/ Sensitivity [%s]: %.5f = %.2f%% " %
                              (label_key, (label_pred_value / actual_specific_lbl_count),
                                           (label_pred_value / actual_specific_lbl_count*100)))
            # For False Negatives
            fpos_count = 0
            spec_label_pred_counts = 0 # For calculating the Precision later
            for error_lbl in self.error_counts_dict.keys():
                # self.logger.debug("Current Label: %s" % label_key)
                # self.logger.debug("Current 1st part of Error-Label: %s" % error_lbl.split("-as-")[0])
                if label_key == error_lbl.split("-as-")[0]:
                    fpos_count += int(self.error_counts_dict[error_lbl])
                    #self.logger.debug("Current False Pos sum: %i" % fpos_count)
                # For Counting the Precision Later
                if label_key == error_lbl.split("-as-")[1]:
                    spec_label_pred_counts += int(self.error_counts_dict[error_lbl])
                    self.logger.debug("Current False Pos sum: %i" % fpos_count)
            self.logger.debug("False Positive Sum: %s : %i" % (label_key, fpos_count))
            all_actual_negatives = all_labels_total - actual_specific_lbl_count
            false_neg_rate = fpos_count / all_actual_negatives
            self.logger.info("--> FALSE NEGATIVE RATE [%s]: %.5f = %.2f%%" % (label_key, false_neg_rate, false_neg_rate * 100))

        # Specificity (True Negative Rate)
            correctly_predicted_no = all_true_pos - self.tp_counter_dict[label_key]      # True Negatives
            self.logger.debug("Number predicted no per class [%s]: %i" % (label_key, correctly_predicted_no))
            true_neg_rate = correctly_predicted_no/all_actual_negatives
            self.logger.info("--> TRUE NEGATIVE RATE/ Specificity [%s]: %.5f = %.2f%%" % (label_key, true_neg_rate, true_neg_rate * 100))

        # Precision (Positive predictive value)
            #Get from error counts how many times another label was predicted as label in consideration
            total_predictions_per_label = label_pred_value + spec_label_pred_counts
            self.logger.debug("Total Predictions of a Certain Label [%s]: %i" % (label_key, total_predictions_per_label))
            precision = label_pred_value/ total_predictions_per_label
            self.logger.info("--> PRECISION [%s] : %.5f = %.2f%%" % (label_key, precision, precision * 100))
